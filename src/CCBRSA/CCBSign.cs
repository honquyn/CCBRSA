using System;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace CCBRSA
{
    public class CCBSign
    {
        private readonly string _signerSymbol = "MD5withRSA";
        private string _publicKey;
        private string _privatekey;
        private AsymmetricKeyParameter _publickeyParameter;
        private AsymmetricKeyParameter _privatekeyParameter;

        /// <summary>
        /// 编码
        /// </summary>
        public Encoding Encoding { get; set; } = Encoding.UTF8;

        /// <summary>
        /// 公钥
        /// </summary>
        public string Publickey
        {
            get
            {
                return _publicKey;
            }
            set
            {
                if (string.IsNullOrEmpty(value))
                {
                    throw new ArgumentException("参数不可为空");
                }

                _publicKey = value;
                var publicKeyBytes = HexStrToBytes(_publicKey);
                _publickeyParameter = PublicKeyFactory.CreateKey(publicKeyBytes);
            }
        }

        /// <summary>
        /// 私钥
        /// </summary>
        public string Privatekey
        {
            get
            {
                return _privatekey;
            }
            set
            {
                if (string.IsNullOrEmpty(value))
                {
                    throw new ArgumentException("参数不可为空");
                }

                _privatekey = value;
                var privatekeyBytes = HexStrToBytes(_privatekey);
                _privatekeyParameter = PrivateKeyFactory.CreateKey(privatekeyBytes);
            }
        }

        /// <summary>
        /// 构造函数
        /// </summary>
        public CCBSign()
        {
        }

        /// <summary>
        /// 构造函数
        /// </summary>
        /// <param name="publickey">公钥</param>
        /// <param name="privatekey">私钥</param>
        public CCBSign(string publickey, string privatekey)
        {
            Publickey = publickey;
            Privatekey = privatekey;
        }

        /// <summary>
        /// 签名
        /// </summary>
        /// <param name="data">待签名数据</param>
        /// <returns></returns>
        public string Sign(string data)
        {
            if (string.IsNullOrEmpty(Privatekey))
            {
                throw new ArgumentException("请设置私钥", Privatekey);
            }

            var signer = SignerUtilities.GetSigner(_signerSymbol);
            signer.Init(true, _privatekeyParameter);

            var dataBytes = Encoding.GetBytes(data);
            signer.BlockUpdate(dataBytes, 0, dataBytes.Length);

            var signature = signer.GenerateSignature();
            return BytesToHexStr(signature);
        }

        /// <summary>
        /// 验证
        /// </summary>
        /// <param name="data">待签名数据</param>
        /// <param name="signData">签名数据</param>
        /// <returns></returns>
        public bool Verify(string data, string signData)
        {
            if (string.IsNullOrEmpty(Publickey))
            {
                throw new ArgumentException("请设置公钥", Publickey);
            }

            var signer = SignerUtilities.GetSigner(_signerSymbol);
            signer.Init(false, _publickeyParameter);

            var dataBytes = Encoding.GetBytes(data);
            signer.BlockUpdate(dataBytes, 0, dataBytes.Length);

            var signDataBytes = HexStrToBytes(signData);
            return signer.VerifySignature(signDataBytes);
        }

        private byte[] HexStrToBytes(string s)
        {
            var buffer = new byte[s.Length / 2];
            for (var i = 0; i < s.Length; i += 2)
            {
                buffer[i / 2] = Convert.ToByte(s.Substring(i, 2), 16);
            }

            return buffer;
        }

        private string BytesToHexStr(byte[] data)
        {
            var sb = new StringBuilder(data.Length * 3);
            foreach (var b in data)
            {
                sb.Append(Convert.ToString(b, 16).PadLeft(2, '0'));
            }

            return sb.ToString();
        }
    }
}
