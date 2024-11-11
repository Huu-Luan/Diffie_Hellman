using System;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

class Client
{
    private static readonly string serverIp = "127.0.0.1";
    private static readonly int port = 8080;
    private static readonly ECDiffieHellmanCng diffieHellman = new ECDiffieHellmanCng();

    static void Main(string[] args)
    {
        diffieHellman.KeySize = 256;
        byte[] clientPublicKey = diffieHellman.PublicKey.ToByteArray();

        using (TcpClient client = new TcpClient(serverIp, port))
        using (NetworkStream stream = client.GetStream())
        {
            Console.WriteLine("Connected to server.");

            byte[] serverPublicKey = new byte[72]; 
            stream.Read(serverPublicKey, 0, serverPublicKey.Length);
            Console.WriteLine("Received public key from server.");

            stream.Write(clientPublicKey, 0, clientPublicKey.Length);
            Console.WriteLine("Sent public key to server.");

            var serverKey = CngKey.Import(serverPublicKey, CngKeyBlobFormat.EccPublicBlob);
            byte[] sharedSecret = diffieHellman.DeriveKeyMaterial(serverKey);
            Console.WriteLine("Shared secret key generated.");

            Console.WriteLine("Shared Secret Key: " + Convert.ToBase64String(sharedSecret));

            byte[] encryptedMessage = new byte[256]; 
            stream.Read(encryptedMessage, 0, encryptedMessage.Length);
            string decryptedMessage = DecryptMessage(encryptedMessage, sharedSecret);
            Console.WriteLine("Decrypted message from server: " + decryptedMessage);
        }
    }

    private static string DecryptMessage(byte[] encryptedMessage, byte[] key)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;

            byte[] iv = new byte[aes.BlockSize / 8];
            Array.Copy(encryptedMessage, iv, iv.Length);
            aes.IV = iv;

            using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
            {
                byte[] decryptedBytes = new byte[encryptedMessage.Length - iv.Length];
                decryptor.TransformBlock(encryptedMessage, iv.Length, decryptedBytes.Length, decryptedBytes, 0);
                return Encoding.UTF8.GetString(decryptedBytes).TrimEnd('\0');
            }
        }
    }
}
