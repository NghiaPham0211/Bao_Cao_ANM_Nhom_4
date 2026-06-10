using System.Security.Cryptography;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls("http://localhost:8080");

var app = builder.Build();
app.UseDefaultFiles();
app.UseStaticFiles();

app.MapPost("/api/encrypt", async (HttpRequest request) =>
{
    try
    {
        var form = await request.ReadFormAsync();
        string text    = form["text"].ToString();
        string key     = form["key"].ToString() is { Length: > 0 } k ? k : "key1234567890123";
        string mode    = form["mode"].ToString() is { Length: > 0 } m ? m : "CBC";
        int keySize    = int.TryParse(form["keySize"], out var ks) ? ks : 128;

        var (data, iv) = AesUtils.Encrypt(text, key, mode, keySize);
        return Results.Json(new { status = "success", result = data, iv });
    }
    catch (Exception ex)
    {
        return Results.Json(new { status = "error", message = ex.Message }, statusCode: 400);
    }
});

app.MapPost("/api/decrypt", async (HttpRequest request) =>
{
    try
    {
        var form = await request.ReadFormAsync();
        string text    = form["text"].ToString();
        string key     = form["key"].ToString() is { Length: > 0 } k ? k : "key1234567890123";
        string mode    = form["mode"].ToString() is { Length: > 0 } m ? m : "CBC";
        string iv      = form["iv"].ToString();
        int keySize    = int.TryParse(form["keySize"], out var ks) ? ks : 128;

        string result = AesUtils.Decrypt(text, key, iv, mode, keySize);
        return Results.Json(new { status = "success", result, iv = "" });
    }
    catch (Exception ex)
    {
        return Results.Json(new { status = "error", message = ex.Message }, statusCode: 400);
    }
});

app.MapPost("/api/genkey", async (HttpRequest request) =>
{
    try
    {
        var form = await request.ReadFormAsync();
        int keySize = int.TryParse(form["keySize"], out var ks) ? ks : 128;

        using var aes = Aes.Create();
        aes.KeySize = keySize;
        aes.GenerateKey();
        string key = Convert.ToBase64String(aes.Key);
        return Results.Json(new { status = "success", key });
    }
    catch (Exception ex)
    {
        return Results.Json(new { status = "error", message = ex.Message }, statusCode: 400);
    }
});

app.MapPost("/api/encrypt-file", async (HttpRequest request) =>
{
    try
    {
        var form = await request.ReadFormAsync();
        string key  = form["key"].ToString() is { Length: > 0 } k ? k : "key1234567890123";
        string mode = form["mode"].ToString() is { Length: > 0 } m ? m : "CBC";
        int keySize = int.TryParse(form["keySize"], out var ks) ? ks : 128;

        var file = form.Files["file"];
        if (file == null || file.Length == 0)
            return Results.Json(new { status = "error", message = "Khong co file" }, statusCode: 400);

        using var ms = new MemoryStream();
        await file.CopyToAsync(ms);
        byte[] fileBytes = ms.ToArray();

        var (encrypted, iv) = AesUtils.EncryptBytes(fileBytes, key, mode, keySize);

        byte[] output;
        if (mode != "ECB" && iv.Length > 0)
        {
            output = new byte[iv.Length + encrypted.Length];
            Buffer.BlockCopy(iv, 0, output, 0, iv.Length);
            Buffer.BlockCopy(encrypted, 0, output, iv.Length, encrypted.Length);
        }
        else
        {
            output = encrypted;
        }

        return Results.File(output, "application/octet-stream", file.FileName + ".enc");
    }
    catch (Exception ex)
    {
        return Results.Json(new { status = "error", message = ex.Message }, statusCode: 400);
    }
});

app.MapPost("/api/decrypt-file", async (HttpRequest request) =>
{
    try
    {
        var form = await request.ReadFormAsync();
        string key  = form["key"].ToString() is { Length: > 0 } k ? k : "key1234567890123";
        string mode = form["mode"].ToString() is { Length: > 0 } m ? m : "CBC";
        int keySize = int.TryParse(form["keySize"], out var ks) ? ks : 128;

        var file = form.Files["file"];
        if (file == null || file.Length == 0)
            return Results.Json(new { status = "error", message = "Khong co file" }, statusCode: 400);

        using var ms = new MemoryStream();
        await file.CopyToAsync(ms);
        byte[] fileBytes = ms.ToArray();

        byte[] iv = Array.Empty<byte>();
        byte[] cipherBytes;
        if (mode != "ECB")
        {
            if (fileBytes.Length < 16)
                return Results.Json(new { status = "error", message = "File qua nho hoac khong hop le" }, statusCode: 400);
            iv = new byte[16];
            Buffer.BlockCopy(fileBytes, 0, iv, 0, 16);
            cipherBytes = new byte[fileBytes.Length - 16];
            Buffer.BlockCopy(fileBytes, 16, cipherBytes, 0, cipherBytes.Length);
        }
        else
        {
            cipherBytes = fileBytes;
        }

        byte[] decrypted = AesUtils.DecryptBytes(cipherBytes, key, iv, mode, keySize);

        string filename = file.FileName.EndsWith(".enc")
            ? file.FileName[..^4]
            : "decrypted_" + file.FileName;

        return Results.File(decrypted, "application/octet-stream", filename);
    }
    catch (Exception ex)
    {
        return Results.Json(new { status = "error", message = ex.Message }, statusCode: 400);
    }
});

Console.WriteLine("==========================================");
Console.WriteLine("  AES Demo Web Server dang chay! (C#)");
Console.WriteLine("  Truy cap: http://localhost:8080");
Console.WriteLine("  Nhan Ctrl+C de dung server");
Console.WriteLine("==========================================");

app.Run();

static class AesUtils
{
    public static byte[] DeriveKey(string key, int keySize)
    {
        int size = keySize / 8;
        byte[] src = Encoding.UTF8.GetBytes(key);
        byte[] result = new byte[size];
        for (int i = 0; i < size; i++)
            result[i] = src[i % src.Length];
        return result;
    }

    public static (string Data, string Iv) Encrypt(string plaintext, string key, string mode, int keySize)
    {
        byte[] keyBytes = DeriveKey(key, keySize);
        using var aes = Aes.Create();
        aes.Key = keyBytes;
        aes.Mode = ParseMode(mode);
        aes.Padding = GetPadding(mode);
        if (mode == "CFB") aes.FeedbackSize = 128;

        string ivB64 = "";
        if (mode != "ECB")
        {
            aes.GenerateIV();
            ivB64 = Convert.ToBase64String(aes.IV);
        }

        using var encryptor = aes.CreateEncryptor();
        byte[] plainBytes = Encoding.UTF8.GetBytes(plaintext);
        byte[] encrypted = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
        return (Convert.ToBase64String(encrypted), ivB64);
    }

    public static string Decrypt(string ciphertext, string key, string iv, string mode, int keySize)
    {
        byte[] keyBytes = DeriveKey(key, keySize);
        using var aes = Aes.Create();
        aes.Key = keyBytes;
        aes.Mode = ParseMode(mode);
        aes.Padding = GetPadding(mode);
        if (mode == "CFB") aes.FeedbackSize = 128;

        if (mode != "ECB" && !string.IsNullOrEmpty(iv))
            aes.IV = Convert.FromBase64String(iv);

        using var decryptor = aes.CreateDecryptor();
        byte[] cipherBytes = Convert.FromBase64String(ciphertext);
        byte[] decrypted = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
        return Encoding.UTF8.GetString(decrypted);
    }

    public static (byte[] Data, byte[] Iv) EncryptBytes(byte[] plainBytes, string key, string mode, int keySize)
    {
        byte[] keyBytes = DeriveKey(key, keySize);
        using var aes = Aes.Create();
        aes.Key = keyBytes;
        aes.Mode = ParseMode(mode);
        aes.Padding = GetPadding(mode);
        if (mode == "CFB") aes.FeedbackSize = 128;

        byte[] iv = Array.Empty<byte>();
        if (mode != "ECB")
        {
            aes.GenerateIV();
            iv = aes.IV;
        }

        using var encryptor = aes.CreateEncryptor();
        return (encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length), iv);
    }

    public static byte[] DecryptBytes(byte[] cipherBytes, string key, byte[] iv, string mode, int keySize)
    {
        byte[] keyBytes = DeriveKey(key, keySize);
        using var aes = Aes.Create();
        aes.Key = keyBytes;
        aes.Mode = ParseMode(mode);
        aes.Padding = GetPadding(mode);
        if (mode == "CFB") aes.FeedbackSize = 128;

        if (mode != "ECB" && iv.Length > 0)
            aes.IV = iv;

        using var decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
    }

    static CipherMode ParseMode(string mode) => mode switch
    {
        "CBC" => CipherMode.CBC,
        "ECB" => CipherMode.ECB,
        "CFB" => CipherMode.CFB,
        "OFB" => CipherMode.OFB,
        _ => throw new ArgumentException($"Unsupported mode: {mode}")
    };

    static PaddingMode GetPadding(string mode) => mode switch
    {
        "CFB" or "OFB" => PaddingMode.None,
        _ => PaddingMode.PKCS7
    };
}
