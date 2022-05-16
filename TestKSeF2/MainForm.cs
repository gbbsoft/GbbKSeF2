/*
 * Author: Gbb Software 2022
 */

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace TestKSeF2
{
    public partial class MainForm : Form
    {

        private List<ConfigurationLine> configurations = new();

        private HttpClient httpClient = new();
        private KSeF_Online.Client? ClientOnLine = null;
        private KSeF_Common.Client? ClientCommon = null;
        private KSeF_Batch.Client? ClientBatch = null;
        private DateTimeOffset Challenge_Timestamp;



        public MainForm()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {

            configurationBindingSource.DataSource = Program.Configuration.Lines;

            // send files
            this.Invoice1_textBox.Text = Properties.Settings.Default.Invoice1;

            // daty
            this.QueryHeader_FromDate_dateTimePicker.Value = DateTime.Today.AddDays(-1);
            this.QueryHeader_ToDate_dateTimePicker.Value = DateTime.Today;

            // incremental
            this.QueryFiles_FromDate_dateTimePicker.Value = DateTime.Now.AddDays(-1);
            this.QueryFiles_ToDate_dateTimePicker.Value = DateTime.Now;

        }

        private void MainForm_Shown(object sender, EventArgs e)
        {
            try
            {
                // if no configuration than open form to define configuration
                if (Program.Configuration.Lines.Count == 0)
                    Configuration_button_Click(this, e);

            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void Configuration_button_Click(object sender, EventArgs e)
        {
            try
            {
                ConfigurationForm dlg = new();
                dlg.ShowDialog();
                configurationBindingSource.ResetBindings(false);

            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message);
            }

        }

        private void CreateClient(ConfigurationLine? CurrConf)
        {
            if (CurrConf == null)
                throw new ApplicationException("Wska¿ konfiguracjê!");

            // create Client
            if (httpClient== null)
                httpClient= new HttpClient();

            ClientCommon = new(httpClient);
            ClientCommon.BaseUrl = CurrConf.URL;

            ClientOnLine = new(httpClient);
            ClientOnLine.BaseUrl = CurrConf.URL;

            ClientBatch = new(httpClient);
            ClientBatch.BaseUrl = CurrConf.URL;

        }

        private async void AuthorisationChallenge_button_Click(object sender, EventArgs e)
        {
            try
            {
                ConfigurationLine? CurrConf = (ConfigurationLine?)this.Configuration_listBox.SelectedItem;
                CreateClient(CurrConf);
                ArgumentNullException.ThrowIfNull(ClientOnLine);
                ArgumentNullException.ThrowIfNull(CurrConf);

                this.AuthorisationChallenge_button.Enabled = false;

                // create body
                var CompanyType = new KSeF_Online.SubjectIdentifierByCompanyType();
                CompanyType.Identifier = CurrConf.NIP;
                var body = new KSeF_Online.AuthorisationChallengeRequest();
                body.ContextIdentifier = CompanyType;

                // send
                var resp = await ClientOnLine.Online_session_authorisation_challengeAsync(body);
                this.Challenge_textBox.Text = resp.Challenge;
                Challenge_Timestamp = resp.Timestamp;
                this.Timestamp_textBox.Text = Challenge_Timestamp.LocalDateTime.ToString() ;
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.ToString());
            }
            finally
            {
                this.AuthorisationChallenge_button.Enabled = true;
            }
        }

        private async void InitToken_button_Click(object sender, EventArgs e)
        {
            try
            {
                ArgumentNullException.ThrowIfNull(ClientOnLine);
                ArgumentNullException.ThrowIfNull(ClientBatch);
                ArgumentNullException.ThrowIfNull(ClientCommon);
                ConfigurationLine CurrConf = (ConfigurationLine)this.Configuration_listBox.SelectedItem;

                this.InitToken_button.Enabled = false;

                // create encrypted token
                string EncryptedToken = KSeFHelpers.Create_EncryptedToken(CurrConf.Token, CurrConf.PublicKey, Challenge_Timestamp);

                // create InitSessionTokenRequest
                Stream body = KSeFHelpers.Create_InitSessionTokenRequest(this.Challenge_textBox.Text, CurrConf.NIP, EncryptedToken);

                // call
                var resp = await ClientOnLine.Online_session_session_token_initAsync(body);
                this.TokenSesji_textBox.Text = resp.SessionToken.Token;
                this.ReferenceNo_textBox.Text = resp.ReferenceNumber;

                // session token for other function calls
                ClientOnLine.OurSessionToken = resp.SessionToken.Token;
                //ClientCommon.OurSessionToken = resp.SessionToken.Token;


            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.ToString());
            }
            finally
            {
                this.InitToken_button.Enabled = true;
            }


        }


        private async void GetStatus_button_Click(object sender, EventArgs e)
        {
            try
            {
                ArgumentNullException.ThrowIfNull(ClientOnLine);

                this.GetStatus_button.Enabled = false;

                // call
                var resp = await ClientOnLine.Online_session_session_status_reference_numberAsync(this.ReferenceNo_textBox.Text, 20, 0);

                System.Text.StringBuilder sb = new System.Text.StringBuilder();
                sb.Append(resp.ProcessingCode);
                sb.Append(": ");
                sb.AppendLine(resp.ProcessingDescription);
                sb.Append("NumberOfElements: ");
                sb.AppendLine(resp.NumberOfElements.ToString());
                if (resp.NumberOfElements > 0)
                {
                    sb.AppendLine();
                    sb.AppendLine("ElementReferenceNumber,InvoiceNumber: Code-ProcessingDescription, KsefReferenceNumber, AcquisitionTimestamp");

                    foreach (var itm in resp.InvoiceStatusList)
                    {
                        sb.Append(itm.ElementReferenceNumber);
                        sb.Append(", ");
                        sb.Append(itm.InvoiceNumber);
                        sb.Append(": ");
                        sb.Append(itm.ProcessingCode);
                        sb.Append("-");
                        sb.Append(itm.ProcessingDescription);
                        sb.Append(", ");
                        sb.Append(itm.KsefReferenceNumber);
                        sb.Append(", ");
                        sb.Append(itm.AcquisitionTimestamp.ToLocalTime().ToString());
                        sb.AppendLine();
                    }
                }

                this.Status_textBox.Text = sb.ToString();

            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.ToString());
            }
            finally
            {
                this.GetStatus_button.Enabled = true;
            }


        }

        private async void GetStatus2_button_Click(object sender, EventArgs e)
        {
            try
            {
                if (ClientCommon == null)
                {
                    ConfigurationLine CurrConf = (ConfigurationLine)this.Configuration_listBox.SelectedItem;
                    CreateClient(CurrConf);
                }
                ArgumentNullException.ThrowIfNull(ClientCommon);

                this.GetStatus2_button.Enabled = false;

                // call
                var resp = await ClientCommon.Common_statusAsync(this.ReferenceNo_textBox.Text);

                System.Text.StringBuilder sb = new System.Text.StringBuilder();
                sb.Append(resp.ProcessingCode);
                sb.Append(": ");
                sb.AppendLine(resp.ProcessingDescription);
                sb.AppendLine("UPO: ");
                if (!string.IsNullOrWhiteSpace(resp.Upo))
                {
                    byte[] buf = Convert.FromBase64String(resp.Upo);
                    string s = System.Text.UTF8Encoding.UTF8.GetString(buf);
                    sb.AppendLine(s);
                }

                this.Status_textBox.Text = sb.ToString();

            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.ToString());
            }
            finally
            {
                this.GetStatus2_button.Enabled = true;
            }
        }

        private async void Terminate_button_Click(object sender, EventArgs e)
        {
            try
            {
                ArgumentNullException.ThrowIfNull(ClientOnLine);

                this.Terminate_button.Enabled = false;

                // call
                var resp = await ClientOnLine.Online_session_session_terminate_plainAsync();

                MessageBox.Show(this, resp.ProcessingCode + ": " + resp.ProcessingDescription);

            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.ToString());
            }
            finally
            {
                this.Terminate_button.Enabled = true;
            }
        }

        // ===============================
        // Wysy³anie faktur
        // ==============================

        private void Invoice1_Dlg_button_Click(object sender, EventArgs e)
        {
            try
            {
                OpenFileDialog dlg = new();
                dlg.FileName = this.Invoice1_textBox.Text;
                dlg.DefaultExt = ".xml";
                dlg.Filter = "Pliki .xml|*.xml";
                if (dlg.ShowDialog(this)== DialogResult.OK)
                    this.Invoice1_textBox.Text = dlg.FileName;
            }
            catch(Exception ex)
            {
                MessageBox.Show(this, ex.ToString());
            }

        }



        private async void Invoice1_button_Click(object sender, EventArgs e)
        {
            try
            {
                ArgumentNullException.ThrowIfNull(ClientOnLine);

                Properties.Settings.Default.Invoice1 = this.Invoice1_textBox.Text;
                Properties.Settings.Default.Save();

                this.Invoice1_button.Enabled = false;

                // get file and it's hash
                string Hash;
                int FileSize;
                byte[] FileBody;

                FileBody = File.ReadAllBytes(this.Invoice1_textBox.Text);
                FileSize = FileBody.Length;

                using (SHA256 mySHA256 = SHA256.Create())
                {
                    Hash = Convert.ToBase64String(mySHA256.ComputeHash(FileBody));
                }

                // parameters
                KSeF_Online.HashSHAType HashSHA = new();
                HashSHA.Algorithm = "SHA-256";
                HashSHA.Encoding = "Base64";
                HashSHA.Value = Hash;
                
                KSeF_Online.File1MBHashType InvoiceHash = new();
                InvoiceHash.FileSize = FileSize;
                InvoiceHash.HashSHA = HashSHA;

                KSeF_Online.InvoicePayloadPlainType InvoicePayloadPlainType = new();
                InvoicePayloadPlainType.InvoiceBody = Convert.ToBase64String(FileBody);

                KSeF_Online.SendInvoiceRequest req = new();
                req.InvoiceHash = InvoiceHash;
                req.InvoicePayload = InvoicePayloadPlainType;

                // call                
                var resp = await ClientOnLine.Online_invoice_invoice_sendAsync(req);

                this.Invoice1_RefNo_textBox.Text = resp.ElementReferenceNumber;

            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.ToString());
            }
            finally
            {
                this.Invoice1_button.Enabled = true;
            }
        }

        private async void InvoiceStatus_button_Click_2(object sender, EventArgs e)
        {
            try
            {
                ArgumentNullException.ThrowIfNull(ClientOnLine);

                this.InvoiceStatus_button.Enabled = false;

                // call
                var resp = await ClientOnLine.Online_invoice_invoice_statusAsync(this.Invoice1_RefNo_textBox.Text);

                // result
                System.Text.StringBuilder sb = new System.Text.StringBuilder();
                sb.Append(resp.ProcessingCode);
                sb.Append(": ");
                sb.AppendLine(resp.ProcessingDescription);
                sb.AppendLine();

                sb.Append("KSeF_RefNo:");
                sb.Append(resp.InvoiceStatus.KsefReferenceNumber);
                sb.Append(", AcqTime: ");
                if (resp.InvoiceStatus.AcquisitionTimestamp.HasValue)
                    sb.Append(resp.InvoiceStatus.AcquisitionTimestamp.Value.ToLocalTime().ToString());

                this.InvoiceStatus_textBox.Text = sb.ToString();

            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.ToString());
            }
            finally
            {
                this.InvoiceStatus_button.Enabled = true;
            }
        }
        private async void GetInvoice1_button_Click(object sender, EventArgs e)
        {
            try
            {
                ArgumentNullException.ThrowIfNull(ClientOnLine);

                this.GetInvoice1_button.Enabled = false;

                // call
                using (var resp = await ClientOnLine.Online_invoice_invoice_getAsync(this.KSefRefNo_textBox.Text))
                {
                    // convert stream to string
                    using (StreamReader reader = new StreamReader(resp.Stream, System.Text.Encoding.UTF8))
                    {
                        string text = reader.ReadToEnd();

                        // put text to control
                        this.GetInvoice1_textBox.Text = text;

                        // save to file
                        if (!string.IsNullOrWhiteSpace(this.GetInvoice_FileName_textBox.Text))
                            File.WriteAllText(this.GetInvoice_FileName_textBox.Text, text);
                    }

                }


            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.ToString());
            }
            finally
            {
                this.GetInvoice1_button.Enabled = true;
            }
        }

        private void GetInvoice1_FileName_button_Click(object sender, EventArgs e)
        {
            try
            {
                SaveFileDialog dlg = new();
                dlg.FileName = this.GetInvoice_FileName_textBox.Text;
                dlg.DefaultExt = ".xml";
                dlg.Filter = "Pliki .xml|*.xml";
                if (dlg.ShowDialog(this) == DialogResult.OK)
                    this.GetInvoice_FileName_textBox.Text = dlg.FileName;
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.ToString());
            }

        }

        private async void GetInvoice1AndCorrect_button_Click(object sender, EventArgs e)
        {
            try
            {
                ArgumentNullException.ThrowIfNull(ClientOnLine);

                this.GetInvoice1AndCorrect_button.Enabled = false;

                // call
                var resp = await ClientOnLine.Online_invoice_invoice_getAsync(this.KSefRefNo_textBox.Text);

                // convert stream to string
                using StreamReader reader = new StreamReader(resp.Stream, System.Text.Encoding.UTF8);
                string text = reader.ReadToEnd();

                // create correction invoice
                byte[] buf = KSeFHelpers.CreateCorrection(text,
                                                this.KSefRefNo_textBox.Text,
                                                this.GetInvoice1_CorrNumber_textBox.Text, this.GetInvoice1_CorrReason_textBox.Text);


                // show result
                this.GetInvoice1_textBox.Text = System.Text.UTF8Encoding.UTF8.GetString(buf);

                // save result
                if (!string.IsNullOrWhiteSpace(this.GetInvoice_FileName_textBox.Text))
                {
                    File.WriteAllBytes(this.GetInvoice_FileName_textBox.Text, buf);
                    this.Invoice1_textBox.Text = this.GetInvoice_FileName_textBox.Text; // prepare to resend to KSeF
                }

            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.ToString());
            }
            finally
            {
                this.GetInvoice1AndCorrect_button.Enabled = true;
            }

        }


        // ===============================
        // Odpytywanie o faktury
        // ==============================

        private DateTimeOffset OurConv(DateTime d)
        {
            return new DateTimeOffset(d.Year, d.Month, d.Day, 0, 0, 0, TimeSpan.Zero);
        }

        private async void QueryHeader_button_Click(object sender, EventArgs e)
        {

            try
            {
                ArgumentNullException.ThrowIfNull(ClientOnLine);

                this.QueryHeader_button.Enabled=false;

                // subject
                KSeF_Online.QueryCriteriaInvoiceTypeSubjectType subjectType;
                if (this.QueryHeader_Subject1_radioButton.Checked)
                    subjectType = KSeF_Online.QueryCriteriaInvoiceTypeSubjectType.Subject1;
                else
                    subjectType = KSeF_Online.QueryCriteriaInvoiceTypeSubjectType.Subject2;


                // parameters
                var body = new KSeF_Online.QueryInvoiceRequest()
                {
                    QueryCriteria = new KSeF_Online.QueryCriteriaInvoiceRangeType()
                    {
                        SubjectType = subjectType,
                        InvoicingDateFrom = this.QueryHeader_FromDate_dateTimePicker.Value,
                        InvoicingDateTo = this.QueryHeader_ToDate_dateTimePicker.Value.AddDays(1)

                    }
                };

                // call
                var resp = await ClientOnLine.Online_query_query_invoiceAsync(100, (int)this.QueryHeader_PageNo_numericUpDown.Value, body);

                // result
                System.Text.StringBuilder sb = new System.Text.StringBuilder();
                sb.Append("NumberOfElements: ");
                sb.AppendLine(resp.NumberOfElements.ToString());
                if (resp.NumberOfElements > 0)
                {
                    sb.AppendLine();
                    sb.AppendLine("KsefReferenceNumber, InvoicingDate, AcquisitionTimestamp, From->To, Net, Vat, Gross, InvoiceReferenceNumber");

                    foreach (var itm in resp.InvoiceHeaderList)
                    {
                        sb.Append(itm.KsefReferenceNumber);
                        sb.Append(", ");
                        sb.Append(itm.InvoicingDate); // bez godzin dla +00
                        sb.Append(", ");
                        sb.Append(itm.AcquisitionTimestamp.ToLocalTime());
                        sb.Append(", ");
                        sb.Append(((KSeF_Online.SubjectIdentifierByCompanyType)itm.SubjectBy.IssuedByIdentifier).Identifier);
                        sb.Append("->");
                        sb.Append(((KSeF_Online.SubjectIdentifierToCompanyType)itm.SubjectTo.IssuedToIdentifier).Identifier);
                        sb.Append(", ");
                        sb.Append(itm.Net);
                        sb.Append(", ");
                        sb.Append(itm.Vat);
                        sb.Append(", ");
                        sb.Append(itm.Gross);
                        sb.Append(", ");
                        sb.Append(itm.InvoiceReferenceNumber);
                        sb.AppendLine();
                    }
                }

                this.QueryHeader_textBox.Text = sb.ToString();

            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.ToString());
            }
            finally
            {
                this.QueryHeader_button.Enabled = true;
            }
        }

        private async void QueryFiles_Init_button_Click_1(object sender, EventArgs e)
        {
            try
            {
                ArgumentNullException.ThrowIfNull(ClientOnLine);

                this.QueryFiles_File_button.Enabled = false;

                // parameters
                KSeF_Online.QueryInvoiceRequest body = new()
                {
                    QueryCriteria = new KSeF_Online.QueryCriteriaInvoiceIncrementalType()
                    {
                        SubjectType = KSeF_Online.QueryCriteriaInvoiceTypeSubjectType.Subject2,
                        AcquisitionTimestampThresholdFrom = this.QueryFiles_FromDate_dateTimePicker.Value,
                        AcquisitionTimestampThresholdTo = this.QueryFiles_ToDate_dateTimePicker.Value

                    }
                };

                // call
                var resp = await ClientOnLine.Online_query_query_invoice_initAsync(body);

                // result
                this.QueryFiles_RefNo_textBox.Text = resp.ElementReferenceNumber;

            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.ToString());
            }
            finally
            {
                this.QueryFiles_File_button.Enabled = true;
            }

        }


        private async void QueryFiles_Status_button_Click(object sender, EventArgs e)
        {
            try
            {
                ArgumentNullException.ThrowIfNull(ClientOnLine);

                this.QueryFiles_Status_button.Enabled = false;

                // call
                var resp = await ClientOnLine.Online_query_query_invoice_statusAsync(this.QueryFiles_RefNo_textBox.Text);


                // result
                System.Text.StringBuilder sb = new System.Text.StringBuilder();
                sb.Append(resp.ProcessingCode);
                sb.Append(": ");
                sb.AppendLine(resp.ProcessingDescription);
                sb.Append("NumberOfElements: ");
                sb.AppendLine(resp.NumberOfElements.ToString());
                sb.Append("NumberOfParts: ");
                sb.AppendLine(resp.NumberOfParts.ToString());
                if (resp.NumberOfParts > 0)
                {
                    sb.AppendLine();
                    sb.AppendLine("PartReferenceNumber,PartName, PartNumber, PartExpiration, FileSize, PartRangeFrom, PartRangeTo");

                    foreach (var itm in resp.PartList)
                    {
                        sb.Append(itm.PartReferenceNumber);
                        sb.Append(", ");
                        sb.Append(itm.PartName);
                        sb.Append(": ");
                        sb.Append(itm.PartNumber);
                        sb.Append("-");
                        sb.Append(itm.PartExpiration);
                        sb.Append(", ");
                        sb.Append(itm.PlainPartHash.FileSize);
                        sb.Append(", ");
                        sb.Append(itm.PartRangeFrom);
                        sb.Append(", ");
                        sb.Append(itm.PartRangeTo);
                        sb.AppendLine();
                    }
                }

                this.QueryFiles_Status_textBox.Text = sb.ToString();

            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.ToString());
            }
            finally
            {
                this.QueryFiles_Status_button.Enabled = true;
            }
        }

        private void QueryFiles_File_button_Click(object sender, EventArgs e)
        {
            try
            {
                SaveFileDialog dlg = new();
                dlg.FileName = this.QueryFiles_File_textBox.Text;
                dlg.DefaultExt = ".zip";
                dlg.Filter = "Plik .zip|*.zip";
                if (dlg.ShowDialog(this) == DialogResult.OK)
                    this.QueryFiles_File_textBox.Text = dlg.FileName;
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.ToString());
            }

        }

        private async void QueryFiles_Get_button_Click(object sender, EventArgs e)
        {
            try
            {
                ArgumentNullException.ThrowIfNull(ClientOnLine);

                this.QueryFiles_Get_button.Enabled = false;

                // call
                var resp = await ClientOnLine.Online_query_query_invoice_statusAsync(this.QueryFiles_RefNo_textBox.Text);

                this.QueryFiles_Status_textBox.Text = $"NumberOfElements={resp.NumberOfElements}\r\nNumberOfParts={resp.NumberOfParts}\r\n";


                if (resp.NumberOfElements == 0)
                    throw new ApplicationException("No files, yes");

                using (SHA256 mySHA256 = SHA256.Create())
                {
                    int PartNo = 0;
                    foreach (var itm in resp.PartList)
                    {
                        PartNo++;
                        this.QueryFiles_Status_textBox.AppendText($"PartNo={PartNo}\r\n");

                        // file name
                        string FileName = this.QueryFiles_File_textBox.Text;
                        string path = Path.GetDirectoryName(FileName) ?? "";
                        string? Name = Path.GetFileNameWithoutExtension(FileName);
                        string Ext = Path.GetExtension(FileName);
                        FileName = Path.Combine(path, Name + "_" + PartNo + Ext);


                        // get
                        var resp2 = await ClientOnLine.Online_query_query_invoice_fetchAsync(this.QueryFiles_RefNo_textBox.Text, itm.PartReferenceNumber);

                        // check hash
                        if (itm.PlainPartHash.HashSHA.Algorithm != "SHA-256")
                            throw new ApplicationException("Unknown hash algorithm: " + itm.PlainPartHash.HashSHA.Algorithm);
                        var Hash = Convert.ToBase64String(mySHA256.ComputeHash(resp2.Stream));
                        if (Hash != itm.PlainPartHash.HashSHA.Value)
                            throw new ApplicationException("Wrong Hash!");

                        // save stream to file
                        resp2.Stream.Position = 0;
                        using (var fs = new FileStream(FileName, FileMode.Create, FileAccess.Write, FileShare.Read))
                        {
                            resp2.Stream.CopyTo(fs);
                            fs.Close();
                        }
                    }

                    MessageBox.Show(this, $"Iloœæ pobranych plików: {PartNo}");

                }




            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.ToString());
            }
            finally
            {
                this.QueryFiles_Get_button.Enabled = true;
            }

        }

        // ===============================
        // Batch - wysy³anie faktur
        // ==============================
        private void Batch_ZipFile_button_Click(object sender, EventArgs e)
        {
            OpenFileDialog dlg = new();
            dlg.FileName = this.Batch_ZipFile_textBox.Text;
            dlg.DefaultExt = ".zip";
            dlg.Filter = "Plik .zip|*.zip";
            if (dlg.ShowDialog(this) == DialogResult.OK)
                this.Batch_ZipFile_textBox.Text = dlg.FileName;

        }

        private void Batch_SignFile_button_Click(object sender, EventArgs e)
        {
            OpenFileDialog dlg = new();
            dlg.FileName = this.Batch_SignFile_textBox.Text;
            dlg.DefaultExt = ".xml";
            dlg.Filter = "Pliki .xml|*.xml";
            if (dlg.ShowDialog(this) == DialogResult.OK)
                this.Batch_SignFile_textBox.Text = dlg.FileName;
        }

        private void Batch_Init_button_Click(object sender, EventArgs e)
        {
            try
            {
                ConfigurationLine CurrConf = (ConfigurationLine)this.Configuration_listBox.SelectedItem;
                CreateClient(CurrConf);
                ArgumentNullException.ThrowIfNull(ClientBatch);


                string ZipFullName = this.Batch_ZipFile_textBox.Text;

                // prepare Hash
                using SHA256 mySHA256 = SHA256.Create();

                // calculate Hash of whole zip
                KSeFHelpers.BatchInit_Params Params = new();
                Params.WholeZip_Hash = KSeFHelpers.CalculateHash(ZipFullName, mySHA256, out Params.WholeZip_Length);
                Params.WholeZip_Name = Path.GetFileName(ZipFullName);

                // prepare AES
                using Aes cipher = Aes.Create();
                cipher.Mode = CipherMode.CBC;  // Ensure the integrity of the ciphertext if using CBC
                cipher.Padding = PaddingMode.PKCS7;
                Params.SymetricAES_Key = KSeFHelpers.EncryptRSA(cipher.Key, CurrConf.PublicKey); // key encrypt by RSA and public key
                Params.SymetricAES_InitVector = cipher.IV;


                // split zip
                byte[] buf = new byte[1024];
                using (var FromFile = new FileStream(ZipFullName, FileMode.Open, FileAccess.Read))
                {
                    long Pos = 0;
                    int OrderNo = 0;
                    while (Pos < FromFile.Length)
                    {

                        // copy part of file and encrypt 
                        OrderNo++;
                        string PartFullName = ZipFullName + "." + OrderNo + ".aes";
                        using (var ToFile = new FileStream(PartFullName, FileMode.Create))
                        {
                            using var encryptor = cipher.CreateEncryptor();
                            using var csEncrypt = new CryptoStream(ToFile, encryptor, CryptoStreamMode.Write);

                            int KBCounter = (int)this.Batch_MaxSize_numericUpDown.Value;
                            while (KBCounter > 0) // no more than KBCounter kilobytes
                            {
                                int r = FromFile.Read(buf, 0, buf.Length);
                                if (r == 0)
                                    break;

                                Pos += r;
                                csEncrypt.Write(buf, 0, r);

                                KBCounter--;
                            }
                        }

                        // file info about part
                        KSeFHelpers.BatchInit_PartFile PartFile = new();
                        PartFile.FileName = Path.GetFileName(PartFullName);
                        PartFile.Hash = KSeFHelpers.CalculateHash(PartFullName, mySHA256, out PartFile.Length);
                        Params.PartFiles.Add(PartFile);

                    }

                }

                // create file
                string XmlFileName = ZipFullName + ".xml";
                KSeFHelpers.Create_BatchInitRequest(CurrConf.NIP, Params, XmlFileName);

                this.Batch_SignFile_textBox.Text = XmlFileName;
                MessageBox.Show("Now, please sign file: " + XmlFileName);



            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.ToString());
            }

        }

        private void Batch_Sign_button_Click(object sender, EventArgs e)
        {
            try
            {
                string XmlFileName = this.Batch_SignFile_textBox.Text;
                if (string.IsNullOrWhiteSpace(XmlFileName))
                    throw new ApplicationException("Nie podano pliku do zaszyforwania (ni¿ej)!");


                // select certificate by user
                X509Store store = new X509Store("MY", StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                X509Certificate2Collection collection = store.Certificates;
                X509Certificate2Collection fcollection = collection.Find(X509FindType.FindByTimeValid, DateTime.Now, true);
                fcollection = fcollection.Find(X509FindType.FindByKeyUsage, (int)X509KeyUsageFlags.DigitalSignature, true);
                X509Certificate2Collection scollection = X509Certificate2UI.SelectFromCollection(fcollection, this.Name, "Wybierz certyfikat, którym chcesz podpisaæ", X509SelectionFlag.SingleSelection, this.Handle);
                if (scollection.Count != 1)
                    return;

                X509Certificate2 cert = scollection[0];


                // Load an XML file into the XmlDocument object.
                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.Load(XmlFileName);

                // calculate sign
                var xmlDigitalSignature = KSeF_Xades.SignWithXAdES(cert, xmlDoc);

                // Append the element to the XmlDocument object.
                ArgumentNullException.ThrowIfNull(xmlDoc.DocumentElement);
                xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));


                // Save the document.
                string NewName = XmlFileName + ".xades.xml";
                xmlDoc.Save(NewName);
                this.Batch_SignFile_textBox.Text = NewName; // save as file to send to KSeF

                MessageBox.Show(this, "Podpisano plik i zapisane jako: " + NewName);


            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.ToString());
            }
        }

        private async void Batch_Send_button_Click(object sender, EventArgs e)
        {
            try
            {
                ConfigurationLine CurrConf = (ConfigurationLine)this.Configuration_listBox.SelectedItem;
                CreateClient(CurrConf);
                ArgumentNullException.ThrowIfNull(ClientBatch);

                this.Batch_Send_button.Enabled = false;

                // parameters
                string path = Path.GetDirectoryName(this.Batch_SignFile_textBox.Text) ?? "";

                // call init
                KSeF_Batch.InitResponse resp;
                using (var XmlFile = new FileStream(this.Batch_SignFile_textBox.Text, FileMode.Open, FileAccess.Read))
                {
                    resp = await ClientBatch.Batch_initAsync(XmlFile);
                }

                // result
                Challenge_Timestamp = resp.Timestamp;
                this.ReferenceNo_textBox.Text = resp.ReferenceNumber;

                // upload files
                foreach (var itm in resp.PackageSignature.PackagePartSignatureList)
                {
                    string FileName = Path.Combine(path, itm.PartFileName);

                    using (var XmlFile = new FileStream(FileName, FileMode.Open, FileAccess.Read))
                    {
                        string PartNumber;
                        int i = itm.Url.LastIndexOf("/");
                        PartNumber = itm.Url.Substring(i + 1);

                        // send
                        ClientBatch.HeaderEntryList = itm.HeaderEntryList; // extra lines in header
                        await ClientBatch.Batch_uploadAsync(resp.ReferenceNumber, PartNumber, XmlFile);
                    }
                }

                // finish
                KSeF_Batch.FinishRequest body = new()
                {
                    ReferenceNumber = resp.ReferenceNumber,
                    Timestamp = resp.Timestamp,
                };
                await ClientBatch.Batch_finishAsync(body);

                // end
                MessageBox.Show(this, "Send!");


            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.ToString());
            }
            finally
            {
                this.Batch_Send_button.Enabled = true;
            }


        }


    }
}