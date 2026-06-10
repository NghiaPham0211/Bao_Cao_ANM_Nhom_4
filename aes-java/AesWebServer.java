
import com.sun.net.httpserver.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;

public class AesWebServer {

    public static void main(String[] args) throws IOException {
        int port = 8080;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", new StaticHandler());
        server.createContext("/api/encrypt", new CryptoHandler(true));
        server.createContext("/api/decrypt", new CryptoHandler(false));
        server.createContext("/api/genkey", new GenKeyHandler());
        server.createContext("/api/encrypt-file", new FileEncryptHandler());
        server.createContext("/api/decrypt-file", new FileDecryptHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("==========================================");
        System.out.println("  AES Demo Web Server dang chay!");
        System.out.println("  Truy cap: http://localhost:" + port);
        System.out.println("  Nhan Ctrl+C de dung server");
        System.out.println("==========================================");
    }

    static class StaticHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange ex) throws IOException {
            String path = ex.getRequestURI().getPath();
            if (path.equals("/") || path.equals("/index.html")) {
                serveFile(ex, "index.html", "text/html; charset=UTF-8");
            } else {
                send(ex, 404, "text/plain", "404 Not Found");
            }
        }

        void serveFile(HttpExchange ex, String filename, String contentType) throws IOException {
            File file = new File(filename);
            if (!file.exists()) {
                send(ex, 404, "text/plain", "File not found: " + filename);
                return;
            }
            byte[] content = Files.readAllBytes(file.toPath());
            ex.getResponseHeaders().set("Content-Type", contentType);
            ex.sendResponseHeaders(200, content.length);
            ex.getResponseBody().write(content);
            ex.getResponseBody().close();
        }
    }

    static class CryptoHandler implements HttpHandler {
        final boolean isEncrypt;

        CryptoHandler(boolean isEncrypt) {
            this.isEncrypt = isEncrypt;
        }

        @Override
        public void handle(HttpExchange ex) throws IOException {
            setCors(ex);
            if ("OPTIONS".equals(ex.getRequestMethod())) {
                ex.sendResponseHeaders(200, -1);
                return;
            }
            if (!"POST".equals(ex.getRequestMethod())) {
                ex.sendResponseHeaders(405, -1);
                return;
            }
            try {
                String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                Map<String, String> p = parseForm(body);

                String text    = p.getOrDefault("text", "");
                String key     = p.getOrDefault("key", "key1234567890123");
                String mode    = p.getOrDefault("mode", "CBC");
                int keySize    = Integer.parseInt(p.getOrDefault("keySize", "128"));
                String iv      = p.getOrDefault("iv", "");

                String result, ivOut = "";
                if (isEncrypt) {
                    AesResult ar = AesUtils.encrypt(text, key, mode, keySize);
                    result = ar.data;
                    ivOut  = ar.iv;
                } else {
                    result = AesUtils.decrypt(text, key, iv, mode, keySize);
                }

                String json = String.format(
                    "{\"status\":\"success\",\"result\":\"%s\",\"iv\":\"%s\"}",
                    escJson(result), escJson(ivOut)
                );
                send(ex, 200, "application/json", json);
            } catch (Exception e) {
                String json = String.format("{\"status\":\"error\",\"message\":\"%s\"}", escJson(e.getMessage()));
                send(ex, 400, "application/json", json);
            }
        }
    }

    // ── File Encrypt Handler ──────────────────────────────────────────────────

    static class FileEncryptHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange ex) throws IOException {
            setCors(ex);
            if ("OPTIONS".equals(ex.getRequestMethod())) { ex.sendResponseHeaders(200, -1); return; }
            if (!"POST".equals(ex.getRequestMethod())) { ex.sendResponseHeaders(405, -1); return; }
            try {
                String contentType = ex.getRequestHeaders().getFirst("Content-Type");
                String boundary = extractBoundary(contentType);
                byte[] body = ex.getRequestBody().readAllBytes();
                List<MultipartPart> parts = parseMultipart(body, boundary);

                String key = "", mode = "CBC";
                int keySize = 128;
                byte[] fileBytes = null;

                for (MultipartPart p : parts) {
                    switch (p.name) {
                        case "key":     key     = new String(p.data, StandardCharsets.UTF_8).trim(); break;
                        case "mode":    mode    = new String(p.data, StandardCharsets.UTF_8).trim(); break;
                        case "keySize": keySize = Integer.parseInt(new String(p.data, StandardCharsets.UTF_8).trim()); break;
                        case "file":    fileBytes = p.data; break;
                    }
                }

                if (fileBytes == null) throw new Exception("Khong tim thay du lieu file");
                if (key.isEmpty())     throw new Exception("Vui long nhap khoa bi mat");

                byte[] encrypted = AesUtils.encryptBytes(fileBytes, key, mode, keySize);

                ex.getResponseHeaders().set("Content-Type", "application/octet-stream");
                ex.getResponseHeaders().set("Content-Disposition", "attachment");
                ex.sendResponseHeaders(200, encrypted.length);
                ex.getResponseBody().write(encrypted);
                ex.getResponseBody().close();
            } catch (Exception e) {
                String json = String.format("{\"status\":\"error\",\"message\":\"%s\"}", escJson(e.getMessage()));
                send(ex, 400, "application/json", json);
            }
        }
    }

    // ── File Decrypt Handler ──────────────────────────────────────────────────

    static class FileDecryptHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange ex) throws IOException {
            setCors(ex);
            if ("OPTIONS".equals(ex.getRequestMethod())) { ex.sendResponseHeaders(200, -1); return; }
            if (!"POST".equals(ex.getRequestMethod())) { ex.sendResponseHeaders(405, -1); return; }
            try {
                String contentType = ex.getRequestHeaders().getFirst("Content-Type");
                String boundary = extractBoundary(contentType);
                byte[] body = ex.getRequestBody().readAllBytes();
                List<MultipartPart> parts = parseMultipart(body, boundary);

                String key = "";
                byte[] fileBytes = null;

                for (MultipartPart p : parts) {
                    switch (p.name) {
                        case "key":  key       = new String(p.data, StandardCharsets.UTF_8).trim(); break;
                        case "file": fileBytes = p.data; break;
                    }
                }

                if (fileBytes == null) throw new Exception("Khong tim thay du lieu file");
                if (key.isEmpty())     throw new Exception("Vui long nhap khoa bi mat");

                byte[] decrypted = AesUtils.decryptBytes(fileBytes, key);

                ex.getResponseHeaders().set("Content-Type", "application/octet-stream");
                ex.getResponseHeaders().set("Content-Disposition", "attachment");
                ex.sendResponseHeaders(200, decrypted.length);
                ex.getResponseBody().write(decrypted);
                ex.getResponseBody().close();
            } catch (Exception e) {
                String json = String.format("{\"status\":\"error\",\"message\":\"%s\"}", escJson(e.getMessage()));
                send(ex, 400, "application/json", json);
            }
        }
    }

    // ── Multipart helpers ─────────────────────────────────────────────────────

    static String extractBoundary(String contentType) throws IOException {
        if (contentType == null) throw new IOException("Thieu Content-Type");
        for (String part : contentType.split(";")) {
            part = part.trim();
            if (part.startsWith("boundary=")) return part.substring(9);
        }
        throw new IOException("Khong tim thay boundary trong Content-Type");
    }

    static class MultipartPart {
        String name = "", filename = "";
        byte[] data = new byte[0];
    }

    static List<MultipartPart> parseMultipart(byte[] body, String boundary) {
        List<MultipartPart> parts = new ArrayList<>();
        byte[] delim = ("\r\n--" + boundary).getBytes(StandardCharsets.ISO_8859_1);
        byte[] start = ("--" + boundary).getBytes(StandardCharsets.ISO_8859_1);

        int pos = indexOf(body, start, 0);
        if (pos < 0) return parts;
        pos += start.length;

        while (pos < body.length) {
            if (pos + 1 < body.length && body[pos] == '-' && body[pos + 1] == '-') break;
            if (pos + 1 < body.length && body[pos] == '\r' && body[pos + 1] == '\n') pos += 2;
            else break;

            byte[] headerEnd = {'\r', '\n', '\r', '\n'};
            int hEnd = indexOf(body, headerEnd, pos);
            if (hEnd < 0) break;

            String headers = new String(body, pos, hEnd - pos, StandardCharsets.ISO_8859_1);
            pos = hEnd + 4;

            int next = indexOf(body, delim, pos);
            byte[] data = next >= 0
                ? Arrays.copyOfRange(body, pos, next)
                : Arrays.copyOfRange(body, pos, body.length);
            pos = next >= 0 ? next + delim.length : body.length;

            MultipartPart part = new MultipartPart();
            part.data = data;
            for (String line : headers.split("\r\n")) {
                if (line.toLowerCase().startsWith("content-disposition:")) {
                    for (String token : line.split(";")) {
                        token = token.trim();
                        if (token.startsWith("name=\"") && token.endsWith("\""))
                            part.name = token.substring(6, token.length() - 1);
                        else if (token.startsWith("filename=\"") && token.endsWith("\""))
                            part.filename = token.substring(10, token.length() - 1);
                    }
                }
            }
            parts.add(part);
        }
        return parts;
    }

    static int indexOf(byte[] src, byte[] pat, int start) {
        outer:
        for (int i = start; i <= src.length - pat.length; i++) {
            for (int j = 0; j < pat.length; j++) {
                if (src[i + j] != pat[j]) continue outer;
            }
            return i;
        }
        return -1;
    }

    // ── Shared utilities ──────────────────────────────────────────────────────

    static class GenKeyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange ex) throws IOException {
            setCors(ex);
            if ("OPTIONS".equals(ex.getRequestMethod())) { ex.sendResponseHeaders(200, -1); return; }
            try {
                String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                Map<String, String> p = parseForm(body);
                int keySize = Integer.parseInt(p.getOrDefault("keySize", "128"));
                javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("AES");
                kg.init(keySize);
                String key = Base64.getEncoder().encodeToString(kg.generateKey().getEncoded());
                send(ex, 200, "application/json", "{\"status\":\"success\",\"key\":\"" + key + "\"}");
            } catch (Exception e) {
                send(ex, 400, "application/json", "{\"status\":\"error\",\"message\":\"" + escJson(e.getMessage()) + "\"}");
            }
        }
    }

    static void setCors(HttpExchange ex) {
        ex.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        ex.getResponseHeaders().set("Access-Control-Allow-Methods", "POST, OPTIONS");
        ex.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type");
    }

    static void send(HttpExchange ex, int status, String contentType, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", contentType + "; charset=UTF-8");
        ex.sendResponseHeaders(status, bytes.length);
        ex.getResponseBody().write(bytes);
        ex.getResponseBody().close();
    }

    static Map<String, String> parseForm(String body) throws UnsupportedEncodingException {
        Map<String, String> map = new HashMap<>();
        for (String pair : body.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                map.put(URLDecoder.decode(kv[0], "UTF-8"), URLDecoder.decode(kv[1], "UTF-8"));
            }
        }
        return map;
    }

    static String escJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}

// ── AesResult ─────────────────────────────────────────────────────────────────

class AesResult {
    String data, iv;
    AesResult(String data, String iv) { this.data = data; this.iv = iv; }
}

// ── AesUtils ──────────────────────────────────────────────────────────────────

class AesUtils {

    // File format: [4 magic "AESF"][1 mode index][2 keySize big-endian][16 IV][encrypted bytes]
    static final byte[] MAGIC = {'A', 'E', 'S', 'F'};
    static final String[] MODE_NAMES = {"CBC", "ECB", "CFB", "OFB"};
    static final int HEADER_LEN = 23; // 4 + 1 + 2 + 16

    static byte[] deriveKey(String key, int keySize) {
        int size = keySize / 8;
        byte[] src = key.getBytes(StandardCharsets.UTF_8);
        byte[] result = new byte[size];
        for (int i = 0; i < size; i++) {
            result[i] = src[i % src.length];
        }
        return result;
    }

    // ── Text encrypt/decrypt (existing) ──────────────────────────────────────

    static AesResult encrypt(String plaintext, String key, String mode, int keySize) throws Exception {
        SecretKeySpec sks = new SecretKeySpec(deriveKey(key, keySize), "AES");
        Cipher cipher = Cipher.getInstance("AES/" + mode + "/PKCS5Padding");
        String ivB64 = "";
        if ("ECB".equals(mode)) {
            cipher.init(Cipher.ENCRYPT_MODE, sks);
        } else {
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            cipher.init(Cipher.ENCRYPT_MODE, sks, new IvParameterSpec(iv));
            ivB64 = Base64.getEncoder().encodeToString(iv);
        }
        byte[] enc = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return new AesResult(Base64.getEncoder().encodeToString(enc), ivB64);
    }

    static String decrypt(String ciphertext, String key, String iv, String mode, int keySize) throws Exception {
        SecretKeySpec sks = new SecretKeySpec(deriveKey(key, keySize), "AES");
        Cipher cipher = Cipher.getInstance("AES/" + mode + "/PKCS5Padding");
        if ("ECB".equals(mode)) {
            cipher.init(Cipher.DECRYPT_MODE, sks);
        } else {
            byte[] ivBytes = Base64.getDecoder().decode(iv);
            cipher.init(Cipher.DECRYPT_MODE, sks, new IvParameterSpec(ivBytes));
        }
        byte[] dec = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(dec, StandardCharsets.UTF_8);
    }

    // ── File encrypt/decrypt (new) ────────────────────────────────────────────

    static byte[] encryptBytes(byte[] plain, String key, String mode, int keySize) throws Exception {
        SecretKeySpec sks = new SecretKeySpec(deriveKey(key, keySize), "AES");
        Cipher cipher = Cipher.getInstance("AES/" + mode + "/PKCS5Padding");
        byte[] iv = new byte[16];
        if ("ECB".equals(mode)) {
            cipher.init(Cipher.ENCRYPT_MODE, sks);
        } else {
            new SecureRandom().nextBytes(iv);
            cipher.init(Cipher.ENCRYPT_MODE, sks, new IvParameterSpec(iv));
        }
        byte[] encData = cipher.doFinal(plain);

        int modeIdx = 0;
        for (int i = 0; i < MODE_NAMES.length; i++) {
            if (MODE_NAMES[i].equals(mode)) { modeIdx = i; break; }
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream(HEADER_LEN + encData.length);
        out.write(MAGIC);                       // 4 bytes: magic
        out.write(modeIdx);                     // 1 byte:  mode index
        out.write((keySize >> 8) & 0xFF);       // 2 bytes: keySize big-endian
        out.write(keySize & 0xFF);
        out.write(iv);                          // 16 bytes: IV (zeros for ECB)
        out.write(encData);
        return out.toByteArray();
    }

    static byte[] decryptBytes(byte[] fileBytes, String key) throws Exception {
        if (fileBytes.length < HEADER_LEN)
            throw new Exception("File qua ngan hoac khong dung dinh dang AESF");

        for (int i = 0; i < MAGIC.length; i++) {
            if (fileBytes[i] != MAGIC[i])
                throw new Exception("File khong phai dinh dang AESF (sai magic bytes)");
        }

        int modeIdx = fileBytes[4] & 0xFF;
        if (modeIdx >= MODE_NAMES.length)
            throw new Exception("Che do ma hoa khong hop le trong file");
        String mode = MODE_NAMES[modeIdx];

        int keySize = ((fileBytes[5] & 0xFF) << 8) | (fileBytes[6] & 0xFF);
        byte[] iv      = Arrays.copyOfRange(fileBytes, 7, 23);
        byte[] encData = Arrays.copyOfRange(fileBytes, 23, fileBytes.length);

        SecretKeySpec sks = new SecretKeySpec(deriveKey(key, keySize), "AES");
        Cipher cipher = Cipher.getInstance("AES/" + mode + "/PKCS5Padding");
        if ("ECB".equals(mode)) {
            cipher.init(Cipher.DECRYPT_MODE, sks);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, sks, new IvParameterSpec(iv));
        }
        try {
            return cipher.doFinal(encData);
        } catch (BadPaddingException e) {
            throw new Exception("Giai ma that bai: sai khoa hoac file bi hong");
        }
    }
}
