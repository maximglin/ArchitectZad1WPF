using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.IO;

namespace ArchitectZad1WPF
{

    /// <summary>
    /// Класс для работы с сертификатами
    /// </summary>
    public class Cryption
    {
        /// <summary>
        /// сертификат
        /// </summary>
        X509Certificate2 cert;

        //  Logging log;
        /// <summary>
        /// Поиск сертификата. Если он есть в локальном хранилище то выгружае
        /// </summary>
        public Cryption(String Name)
        {

            //   log = new Logging();      
            try
            {
                cert = LoadCertificate(StoreLocation.CurrentUser, "CN=" + Name);

            }
            catch (Exception e)
            {

                Console.WriteLine("ERROR! " + e.ToString());
            }
        }

        public X509Certificate2 MyCertificate() { return cert; }


        /// <summary>
        /// Загрузка сертификата из учетной записи компьютера
        /// </summary>
        private X509Certificate2 LoadCertificate(StoreLocation storeLocation, string certificateName)
        {
            X509Store store = new X509Store(storeLocation);
            store.Open(OpenFlags.ReadOnly);
            X509CertificateCollection certCollection = store.Certificates;
            X509Certificate2 x509 = null;

            foreach (X509Certificate2 c in certCollection)
            {
                if (c.Subject.Contains(certificateName))
                {
                    x509 = c;
                    Console.WriteLine("Сертификат найден: " + certificateName);
                    break;
                }
                else
                {
                    Console.WriteLine("Сертификат не найден: " + certificateName);
                }
            }

            if (x509 == null)
            {
                store.Close();
            }

            return x509;
        }

        public X509Certificate2 LoadresCertificate(string certificateName)
        {
            X509Store store = new X509Store(StoreName.AddressBook, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            X509CertificateCollection certCollection = store.Certificates;
            X509Certificate2 x509 = null;

            foreach (X509Certificate2 c in certCollection)
            {
                if (c.Subject.Contains(certificateName))
                {
                    x509 = c;
                    break;
                }
                else
                {
                    Console.WriteLine("Сертификат не найден: " + certificateName);
                }
            }

            if (x509 == null)
            {
                store.Close();
            }
            return x509;
        }

        /// <summary>
        /// Проверка валидности сертификата
        /// </summary>
        public bool ValidateCertificate(X509Certificate2 x509)
        {
            bool valid = false;
            DateTime timeSert = DateTime.Parse(x509.GetExpirationDateString());

            if (DateTime.Now.CompareTo(timeSert) < 0)
            {
                Console.WriteLine("Сертификат валиден. Текущая дата: " + DateTime.Now.ToString() + " Дата сертификата: " + timeSert.ToString());
                valid = true;
            }
            else { Console.WriteLine("Сертификат не валиден. Текущая дата: " + DateTime.Now.ToString() + " Дата сертификата: " + timeSert.ToString()); }

            return valid;
        }

        /// <summary>
        /// Подписываем файл с помощью закрытого ключа своего ЭЦП
        /// </summary>
        public byte[] SignByCertificate(byte[] fileForSign, X509Certificate2 x509)
        {

            // create ContentInfo
            ContentInfo content = new ContentInfo(fileForSign);

            // SignedCms represents signed data
            SignedCms signedMessage = new SignedCms(content);

            // create a signer
            CmsSigner signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, x509);

            // sign the data
            signedMessage.ComputeSignature(signer, false);

            // create PKCS #7 byte array
            byte[] signedBytes = signedMessage.Encode();

            // return signed data
            return signedBytes;
        }
        /// <summary>
        /// Подписываем файл с помощью открытого ключа ЭЦП получателя
        /// </summary>
        /// <param name="fileForCrypt"></param>
        /// <param name="x509res"></param>
        /// <returns></returns>
        public byte[] SignByRecipentCertificate(byte[] fileForCrypt, X509Certificate2 x509res)
        {
            // Помещаем сообщение в объект ContentInfo 
            // Это требуется для создания объекта EnvelopedCms.
            ContentInfo contentInfo = new ContentInfo(fileForCrypt);

            // Создаем объект EnvelopedCms, передавая ему
            // только что созданный объект ContentInfo.
            // Используем идентификацию получателя (SubjectIdentifierType)
            // по умолчанию (IssuerAndSerialNumber).
            // Не устанавливаем алгоритм зашифрования тела сообщения:
            // ContentEncryptionAlgorithm устанавливается в 
            // RSA_DES_EDE3_CBC, несмотря на это, при зашифровании
            // сообщения в адрес получателя с ГОСТ сертификатом,
            // будет использован алгоритм GOST 28147-89.
            EnvelopedCms envelopedCms = new EnvelopedCms(contentInfo);

            // Создаем объект CmsRecipient, который 
            // идентифицирует получателя зашифрованного сообщения.
            CmsRecipient recip1 = new CmsRecipient(SubjectIdentifierType.IssuerAndSerialNumber, x509res);

            //Console.Write("Зашифровываем данные для одного получателя " + "с именем {0} ...", recip1.Certificate.SubjectName.Name);
            // Зашифровываем сообщение.
            envelopedCms.Encrypt(recip1);
            //Console.WriteLine("Выполнено.");

            // Закодированное EnvelopedCms сообщение содержит
            // зашифрованный текст сообщения и информацию
            // о каждом получателе данного сообщения.
            return envelopedCms.Encode();
        }
        /// <summary>
        /// Шифруем в BASE64
        /// </summary>
        /// <param name="encoded"></param>
        /// <returns></returns>
        public byte[] Base64Encode(byte[] encoded)
        {
            string PKCS7_HEADER = "----- BEGIN PKCS7 ENCRYPTED -----" + Environment.NewLine;
            string PKCS7_FOOTER = Environment.NewLine + "----- END PKCS7 ENCRYPTED -----";

            string base64 = Convert.ToBase64String(encoded);
            StringBuilder formatted = new StringBuilder();
            formatted.Append(PKCS7_HEADER);
            formatted.Append(base64);
            formatted.Append(PKCS7_FOOTER);

            byte[] bytes = Encoding.ASCII.GetBytes(formatted.ToString());


            return bytes;
            // return formatted.ToString();
        }
        /// <summary>
        /// Расшифровывает данные из BASE64
        /// </summary>
        /// <param name="decoded"></param>
        /// <returns></returns>
        public byte[] Base64Decode(byte[] decoded)
        {
            byte[] bytes = Convert.FromBase64String(Encoding.ASCII.GetString(decoded));

            return bytes;
        }

        public byte[] Decode(byte[] file)
        {
            EnvelopedCms signedMessage = new EnvelopedCms();
            signedMessage.Decode(file);
            signedMessage.Decrypt();
            return signedMessage.ContentInfo.Content;
        }

        public byte[] Unsign(byte[] file)
        {
            SignedCms sc = new SignedCms();
            sc.Decode(DetectAndConvertFromBase64(file));
            sc.CheckSignature(true);
            return sc.ContentInfo.Content;
        }

        public byte[] UnsignedByRecipentCertificate(byte[] file)
        {


            EnvelopedCms signedMessage = new EnvelopedCms();
            signedMessage.Decode(file);
            signedMessage.Decrypt();

            SignedCms sc = new SignedCms();
            sc.Decode(DetectAndConvertFromBase64(signedMessage.ContentInfo.Content));
            sc.CheckSignature(true);
            return sc.ContentInfo.Content;
        }

        private byte[] DetectAndConvertFromBase64(byte[] signedBytes)
        {
            byte[] bytes = null;
            try
            {
                if (DetectBase64Encode(signedBytes))
                {
                    bytes = RemovePkcsHeaders(signedBytes);
                    bytes = Base64Decode(bytes);
                }
                else
                {
                    bytes = signedBytes;
                }

            }
            catch (Exception e)
            {
                Console.WriteLine("The file could not be read:");
                Console.WriteLine(e.Message);
            }
            return bytes;
        }



        /// <summary>
        /// удалдение заголовков
        /// </summary>
        /// <param name="body"></param>
        public byte[] RemovePkcsHeaders(byte[] body)
        {
            // удаляем первую строку заголовка "----- BEGIN PKCS7 SIGNED -----"
            // и удаляем последнюю строку "----- END PKCS7 SIGNED -----"
            byte[] temp;
            StringBuilder formatted = new StringBuilder();
            Stream stream = new MemoryStream(body);
            using (var sr = new StreamReader(stream))
            {
                //using (var sw = new BinaryWriter)
                //{
                string line;

                while ((line = sr.ReadLine()) != null)
                {
                    if ((line != "----- BEGIN PKCS7 SIGNED -----") && (line != "----- END PKCS7 SIGNED -----") && (line != "----- BEGIN PKCS7 ENCRYPTED -----") && (line != "----- END PKCS7 ENCRYPTED -----"))

                    {
                        //all += line;
                        formatted.Append(line);
                    }
                }
                // }
            }
            stream.Close();
            // File.Delete(body);
            //  File.Move(tempFile, body);
            temp = Encoding.ASCII.GetBytes(formatted.ToString());
            return temp;
        }

        #region  функции для определения кодировки

        /// <summary>
        /// Определяет закодирован ли файл в BASE64. Смотрит первую строчку.
        /// </summary>
        /// <param name="body"></param>
        /// <returns></returns>
        public bool DetectBase64Encode(byte[] body)
        {

            try
            {
                String firstLine = "";
                Stream stream = new MemoryStream(body);
                using (StreamReader sr = new StreamReader(stream))
                {
                    firstLine = sr.ReadLine();
                }
                stream.Close();
                if (firstLine == "----- BEGIN PKCS7 SIGNED -----" || firstLine == "----- BEGIN PKCS7 ENCRYPTED -----")
                {
                    //RemovePkcsHeaders(body);
                    return true;

                }
                else
                {
                    if (CheckBase64StringSafe(firstLine))
                    {
                        return true;

                    }
                    else
                    {
                        return false;
                    }
                }

            }
            catch (Exception e)
            {
                Console.WriteLine("The file could not be read:");
                Console.WriteLine(e.Message);
                return false;
            }

        }

        private const char Base64Padding = '=';

        private static readonly HashSet<char> Base64Characters = new HashSet<char>()
    {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
    };


        public bool CheckBase64StringSafe(string param)
        {
            if (param == null)
            {
                // null string is not Base64 something
                return false;
            }

            // replace optional CR and LF characters
            ;
            param = param.Replace("\r", String.Empty).Replace("\n", String.Empty);

            if (param.Length == 0 ||
                (param.Length % 4) != 0)
            {
                // Base64 string should not be empty
                // Base64 string length should be multiple of 4
                return false;
            }

            // replace pad chacters
            int lengthNoPadding = param.Length;
            int lengthPadding;

            param = param.TrimEnd(Base64Padding);
            lengthPadding = param.Length;

            if ((lengthNoPadding - lengthPadding) > 2)
            {
                // there should be no more than 2 pad characters
                return false;
            }

            foreach (char c in param)
            {
                if (Base64Characters.Contains(c) == false)
                {
                    // string contains non-Base64 character
                    return false;
                }
            }

            // nothing invalid found
            return true;
        }

        #endregion
    }
}
