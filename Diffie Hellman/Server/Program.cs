using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

class Server
{
    private static readonly int port = 8080;
    private static readonly ECDiffieHellmanCng diffieHellman = new ECDiffieHellmanCng();

    static void Main(string[] args)
    {
        diffieHellman.KeySize = 256;
        byte[] serverPublicKey = diffieHellman.PublicKey.ToByteArray();

        TcpListener server = new TcpListener(IPAddress.Any, port);
        server.Start();
        Console.WriteLine("Server started. Waiting for a connection...");

        using (TcpClient client = server.AcceptTcpClient())
        using (NetworkStream stream = client.GetStream())
        {
            Console.WriteLine("Client connected.");
            stream.Write(serverPublicKey, 0, serverPublicKey.Length);
            Console.WriteLine("Sent public key to client.");

            byte[] clientPublicKey = new byte[72];
            stream.Read(clientPublicKey, 0, clientPublicKey.Length);
            Console.WriteLine("Received public key from client.");

            var clientKey = CngKey.Import(clientPublicKey, CngKeyBlobFormat.EccPublicBlob);
            byte[] sharedSecret = diffieHellman.DeriveKeyMaterial(clientKey);
            Console.WriteLine("Shared secret key generated.");
            Console.WriteLine("Shared Secret Key: " + Convert.ToBase64String(sharedSecret));

            string message = "Hello from Luan!";
            byte[] encryptedMessage = EncryptMessage(message, sharedSecret);
            stream.Write(encryptedMessage, 0, encryptedMessage.Length);
            Console.WriteLine("Encrypted message sent to client.");
        }
        server.Stop();
    }

    private static byte[] EncryptMessage(string message, byte[] key)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.GenerateIV();
            using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
            {
                byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                byte[] encryptedMessage = new byte[aes.IV.Length + messageBytes.Length];

                Array.Copy(aes.IV, 0, encryptedMessage, 0, aes.IV.Length);
                encryptor.TransformBlock(messageBytes, 0, messageBytes.Length, encryptedMessage, aes.IV.Length);

                return encryptedMessage;
            }
        }
    }
}
