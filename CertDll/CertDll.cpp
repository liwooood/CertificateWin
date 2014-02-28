#include "cert_export.h"


void MsgBox(LPCTSTR msg)
{
	MessageBox(NULL, msg, "npCert", MB_OK);
}

void MsgBox(int result)
{
	char buf[10];
	memset(buf, '\0', sizeof(buf));

	sprintf(buf, "%d", result);

	MsgBox(buf);
}

BOOL InstallCertFile(const wchar_t* lpStore, const wchar_t* lpCertFile)
//BOOL InstallCert(LPCTSTR lpStore, LPCTSTR lpCertFile)
{
	DWORD dwMsgAndCertEncodingType;
	DWORD dwContentType;
	DWORD dwFormatType;
	PCCERT_CONTEXT pCertCtx = NULL;
	HCERTSTORE hCertStore = NULL;     

	BOOL bResult = FALSE;


	bResult = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
		lpCertFile,
		CERT_QUERY_CONTENT_FLAG_ALL,
		CERT_QUERY_FORMAT_FLAG_ALL,
		0,
		&dwMsgAndCertEncodingType,
		&dwContentType,
		&dwFormatType,
		NULL,
		NULL, 
		(const void **)&pCertCtx);

	if (!bResult)
	{
		return bResult;
	}


	hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
		0,
		NULL,
		CERT_SYSTEM_STORE_CURRENT_USER,
		lpStore);

	if (hCertStore == NULL)
	{
		return FALSE;
	}

	bResult = CertAddCertificateContextToStore(hCertStore, pCertCtx, CERT_STORE_ADD_ALWAYS, NULL);

	if (pCertCtx)
    {
        CertFreeCertificateContext(pCertCtx);
    }

	if (hCertStore)
		CertCloseStore(hCertStore, 0);

	return bResult;
}

/*
const wchar_t * A2W(const char *c)
{
    const size_t cSize = strlen(c)+1;
    wchar_t* wc = new wchar_t[cSize];
    mbstowcs (wc, c, cSize);

    return wc;
}
*/

wchar_t * A2W_(const char * lpStr)
{
/*
int MultiByteToWideChar(
  _In_       UINT CodePage,
  _In_       DWORD dwFlags,
  _In_       LPCSTR lpMultiByteStr,
  _In_       int cbMultiByte,
  _Out_opt_  LPWSTR lpWideCharStr,
  _In_       int cchWideChar
);
*/
	if (lpStr == NULL)
		return NULL;

	int len1 = MultiByteToWideChar(CP_ACP, 0, lpStr, -1, NULL, 0);  
//	TRACE("len1 = %d\n", len1);

	//wchar_t* pwstr = new wchar_t[len1];
	wchar_t* pwstr = new wchar_t[len1 + 1];
	int len2 = MultiByteToWideChar(CP_ACP, 0, lpStr, -1, pwstr, len1); 
	pwstr[len2] = '\0';
//	TRACE("len2 = %d\n", len2);
	
	
	return pwstr;
}

int __stdcall InstallRootCert(LPCTSTR lpCertFile)
{

	//MessageBox(NULL, lpCertFile, _T("InstallRootCert"), MB_OK);


	const wchar_t* pwCertFile = A2W_(lpCertFile);

	if (!InstallCertFile(L"ROOT", pwCertFile))
	{
		return 0;
	}

	return 1;
}	

int __stdcall InstallCACert(LPCTSTR lpCertFile)
{
	const wchar_t* pwCertFile = A2W_(lpCertFile);


	if (!InstallCertFile(L"CA", pwCertFile))
	{
		return 0;
	}
	
	return 1;
}


int __stdcall AddTrustedWebSite(LPCTSTR lpWebSite)
{
	int nRet = 0;

	// support http & https
	LPCTSTR lpSubKey = _T("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\2");
	HKEY hKey;
	nRet = RegOpenKeyEx(HKEY_CURRENT_USER, lpSubKey, 0, KEY_ALL_ACCESS, &hKey);
	if (nRet != ERROR_SUCCESS)
		return 0;
	DWORD dwData = 67;
	RegSetValueEx(hKey, _T("Flags"), 0, REG_DWORD, (const BYTE *) &dwData, sizeof(DWORD));
	RegCloseKey(hKey);


	 ::CoInitialize(NULL);

	 HRESULT hResult = S_OK;
	 IInternetSecurityManager *pSecurityManager = NULL;

	 hResult = CoCreateInstance( CLSID_InternetSecurityManager, 
                              NULL, 
                              CLSCTX_INPROC_SERVER,
                              IID_IInternetSecurityManager,
                              (void **)&pSecurityManager );

	if (SUCCEEDED(hResult))	
    {
		/*
		hResult=pSecurityManager->SetZoneMapping(URLZONE_ESC_FLAG|URLZONE_TRUSTED,
												 lpWebSite,
												 SZM_CREATE );
												 */
		const wchar_t* pwWebSite = A2W_(lpWebSite);

		hResult=pSecurityManager->SetZoneMapping(URLZONE_TRUSTED,
												 pwWebSite,
												 SZM_CREATE );

		if (SUCCEEDED(hResult))
		{
			nRet = 1;
		}
		else
		{
			nRet = 0;
		}
    
      pSecurityManager->Release();
    }

	 ::CoUninitialize();

	 return nRet;
}

int __stdcall WriteInstallLog(LPCTSTR lpFileName, LPCTSTR lpLog)
{
	std::ofstream outfile(lpFileName, std::ios_base::app);
	if (outfile.is_open())
	{

		outfile << "内容：" << lpLog << "\n";
			

		outfile.close();
		return 1;
	}

	return 0;
}

PCCERT_CONTEXT SelectCertByDN(wchar_t *  Store, LPCTSTR pDN)
{
	HCERTSTORE       hCertStore = NULL;     
	PCCERT_CONTEXT   pCertContext = NULL; 
	



	hCertStore = CertOpenStore(
     CERT_STORE_PROV_SYSTEM, 
     0,                      // Encoding type not needed 
                             // with this PROV.
     NULL,                   // Accept the default HCRYPTPROV. 
     CERT_SYSTEM_STORE_CURRENT_USER,
                             // Set the system store location in 
                             // the registry.
     Store);  

	if (hCertStore == NULL)
		return NULL;

	
	while (pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext))
	{
		DWORD cbSize;

		cbSize = CertNameToStr(pCertContext->dwCertEncodingType,
			&(pCertContext->pCertInfo->Subject),
			CERT_OID_NAME_STR,
			NULL,
			0);

		LPTSTR pszString;
		if (!(pszString = (LPTSTR) malloc(cbSize * sizeof(TCHAR))) )
		{
		}

		cbSize = CertNameToStr(pCertContext->dwCertEncodingType,
			&(pCertContext->pCertInfo->Subject),
			CERT_X500_NAME_STR,
			pszString,
			cbSize);

		if(pCertContext)
		{
	//		CertFreeCertificateContext(pCertContext);
		}

		//if (_tcscmp(pDN, pszString) == 0)
		if (strcmp(pDN, pszString) == 0)
		{
			free(pszString);

			if(hCertStore)
			{
				CertCloseStore(hCertStore, 0);
			}
			// 成功
			return pCertContext;
		}
		else
		{
			//AfxMessageBox(pszString);

			free(pszString);

			
		}
	} // end while


	if(hCertStore)
	{
		CertCloseStore(hCertStore, 0);
	}

	return NULL;
}

int __stdcall  FindCertByDN(LPCTSTR Store, LPCTSTR DN)
{
	

	// TODO: 在此添加调度处理程序代码
	PCCERT_CONTEXT   pCertContext = NULL; 
	
	if (strcmp(Store, "ROOT") == 0)
		pCertContext = SelectCertByDN(L"ROOT", DN);
	else if (strcmp(Store, "CA") == 0)
		pCertContext = SelectCertByDN(L"CA", DN);

	else if (strcmp(Store, "MY") == 0)
		pCertContext = SelectCertByDN(L"MY", DN);
	else
		return 0;

	if (pCertContext == NULL)
		return 0;

	return 1;
}

int __stdcall CreateCSRWinxp(LPTSTR result)
{

	
	int nRet = 0;

	HRESULT				hr;
	CRYPT_DATA_BLOB		MyB64Blob = { 0, NULL };
	CRYPT_DATA_BLOB		MyBlob = { 0, NULL };
	
	LPWSTR				pkcs10 = NULL;

	IEnroll4*			CertEnroll = NULL;
	 ICEnroll4 * pEnroll = NULL;
	 
	 //std::ofstream myfile("pkcs10.txt");


	hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	 //hr = ::CoInitialize(NULL);
	if (FAILED(hr))
	{
		MsgBox(_T("CoInitializeEx"));
		goto error;
	}

	
	hr = CoCreateInstance(CLSID_CEnroll,NULL,CLSCTX_INPROC_SERVER,IID_IEnroll4,(void **)&CertEnroll);
	//hr = CoCreateInstance(CLSID_CEnroll,NULL,CLSCTX_INPROC_SERVER,IID_ICEnroll4,(void **)&pEnroll);
	if (FAILED(hr))
	{
		MsgBox(_T("CoCreateInstance"));
		//MessageBox("CoCreateInstance error");
		goto error;

	}

	//CertEnroll->install

	LPWSTR	wszCSPName		= L"Microsoft Enhanced Cryptographic Provider v1.0";
	hr = CertEnroll->put_ProviderNameWStr(wszCSPName);
	
	if (FAILED(hr))
	{
	
		MsgBox(_T("put_ProviderNameWStr"));
		goto error;
	}

	DWORD	dwKeySpec		= AT_SIGNATURE;
	// Key specification either AT_KEYEXCHANGE / AT_SIGNATURE
	hr=CertEnroll->put_KeySpec( dwKeySpec );
    if(FAILED(hr))
	{
		
		MsgBox(_T("put_KeySpec"));
		goto error;
	}

	LPWSTR	wszTemplateName	= L"EFS";
	// ClientAuth
	hr = CertEnroll->AddCertTypeToRequestWStr(wszTemplateName);
	
	if (FAILED(hr))
	{
		MsgBox(_T("AddCertTypeToRequestWStr"));
		goto error;
	}
	
	DWORD	dwProviderType	= PROV_RSA_FULL;
	hr=CertEnroll->put_ProviderType( dwProviderType );
    if(FAILED(hr))
	{
		
		MsgBox(_T("put_ProviderType"));
		goto error;
	}

	hr=CertEnroll->put_KeySpec( dwKeySpec );
    if(FAILED(hr))
	{
		
		MsgBox(_T("put_KeySpec"));
		goto error;
	}

	DWORD	dwKeyLength		= 1024;
	DWORD	dwGenKeyFlags	= ( dwKeyLength << 16 ) | CRYPT_EXPORTABLE;
	hr=CertEnroll->put_GenKeyFlags( dwGenKeyFlags );
    if(FAILED(hr))
	{
		
		MsgBox(_T("put_GenKeyFlags"));
		goto error;
	}
/*
	hr = CertEnroll->put_EnableSMIMECapabilities( TRUE );
    if(FAILED(hr))
	{
		goto error;
	}
*/
	DWORD	dwCreateFlags		= XECR_PKCS10_V2_0;
	LPCWSTR	wszEntityDN		= NULL;
	LPCWSTR	szCertUsage			= L"";
	
	hr=CertEnroll->createRequestWStr( dwCreateFlags, wszEntityDN, szCertUsage, &MyBlob );
	
	//createPKCS10
    if(FAILED(hr))
	{
		MsgBox(_T("createRequestWStr"));;
		goto error;
	}

	
	hr=CertEnroll->binaryBlobToString( CRYPT_STRING_BASE64REQUESTHEADER, &MyBlob, &pkcs10 );
    if(FAILED(hr))
	{
		MsgBox(_T("binaryBlobToString"));
		goto error;
	}

	// 注意这里是MyB64Blog, 不是MyBlob
	MyB64Blob.cbData = WideCharToMultiByte( CP_THREAD_ACP, 0, pkcs10, -1, NULL, 0, NULL, NULL );
	MyB64Blob.pbData = (BYTE*) LocalAlloc( LPTR, MyB64Blob.cbData );

	WideCharToMultiByte( CP_THREAD_ACP, 0, pkcs10, -1, (LPSTR) MyB64Blob.pbData, MyB64Blob.cbData, NULL, NULL );

	strncpy(result, (LPCTSTR) MyB64Blob.pbData, MyB64Blob.cbData);

//	USES_CONVERSION;
//	char * b64 = W2A(OutputString);

	nRet = 1;

//	if (myfile.is_open())
 // {
  //  myfile << b64;
//	MessageBox("申请成功");

//    myfile.close();
 // }


error:
	if ( NULL != MyB64Blob.pbData )
		LocalFree( MyB64Blob.pbData );
	
	if ( NULL != CertEnroll )
		CertEnroll->Release();

	if ( NULL != MyBlob.pbData )
	    LocalFree( MyBlob.pbData );

	if ( NULL != pkcs10 )
		LocalFree( pkcs10 );

	CoUninitialize();

	

	return nRet;
}

int __stdcall CreateCSRWin7(LPTSTR result)
{
	BOOL rc = FALSE;
	return rc;
}

int __stdcall InstallCertWinxp(LPCTSTR Cert)
{
	
	if (Cert == NULL)
		return 0;

	DWORD dwMsgAndCertEncodingType;
	DWORD dwContentType;
	DWORD dwFormatType;
	PCCERT_CONTEXT pCertCtx = NULL;
	HCERTSTORE       hCertStore = NULL; 

	
	size_t len = strlen(Cert);

	DWORD dwCertEncoded = 0;
	DWORD dwSkip, dwFlags;
	if (!CryptStringToBinaryA(Cert, len, CRYPT_STRING_BASE64, NULL, &dwCertEncoded, &dwSkip, &dwFlags))
	{
	
		MsgBox(_T("CryptStringToBinaryA 1"));
		return 0;
	}

	BYTE* pbCertEncoded = (BYTE*) malloc(dwCertEncoded);
	if (!CryptStringToBinaryA(Cert, len, CRYPT_STRING_BASE64, pbCertEncoded, &dwCertEncoded, &dwSkip, &dwFlags))
	{
		MsgBox(_T("CryptStringToBinaryA 2"));
		return 0;
	}

	pCertCtx = CertCreateCertificateContext(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, pbCertEncoded, dwCertEncoded);
	if (pCertCtx == NULL)
	{
		MsgBox(_T("解析证书出错"));
		return 0;
	}

	CRYPTUI_WIZ_IMPORT_SRC_INFO s;
	memset(&s, 0, sizeof(CRYPTUI_WIZ_IMPORT_SRC_INFO));
	s.dwSize = sizeof(CRYPTUI_WIZ_IMPORT_SRC_INFO);
	s.dwSubjectChoice = CRYPTUI_WIZ_IMPORT_SUBJECT_CERT_CONTEXT;
	s.pCertContext = pCertCtx;
	s.dwFlags = CRYPT_EXPORTABLE;

	BOOL bRet = CryptUIWizImport(CRYPTUI_WIZ_NO_UI, NULL, NULL, &s, NULL);
	if (bRet == TRUE)
	{
		MsgBox(_T("import success"));
	}
	else
	{
		MsgBox(_T("import error"));
	}

	return bRet;
}


int __stdcall InstallCertWin7(LPCTSTR Cert)
{
	BOOL rc = FALSE;
	return rc;
}


int __stdcall Sign(LPCTSTR CertDN, LPCTSTR RawData, LPSTR SignResult)
{
	BOOL bRet = FALSE;

	HCERTSTORE       hCertStore = NULL;
	PCCERT_CONTEXT   pCertContext=NULL; 
	HCRYPTPROV hCryptProv = NULL;
	DWORD dwKeySpec = 0;
	HCRYPTHASH hHash = NULL;
	DWORD dwSignLen = 0;
	BYTE * pbSignature = NULL;


		hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
		0,
		NULL,
		CERT_SYSTEM_STORE_CURRENT_USER,
		L"MY");

	if (hCertStore == NULL)
	{
		MsgBox(_T("CertOpenStore"));
		goto error;
	}

	
	///LPCSTR lpszCertSubject = (LPCSTR) "C@1@100001060";

	if(pCertContext=SelectCertByDN(L"MY", CertDN))
	{
	  
	  //pCertContext->pCertInfo->Subject.
	}
	else
	{
		MsgBox(_T("SelectCertByDN"));
		goto error;
	}

	bRet = CryptAcquireCertificatePrivateKey(
			pCertContext,
			0,
			NULL,
			&hCryptProv,
			&dwKeySpec,
			NULL
		);
	if (!bRet)
	{
		MsgBox(_T("CryptAcquireCertificatePrivateKey"));
		goto error;
	}

	int t = dwKeySpec & AT_SIGNATURE;
	if (t != AT_SIGNATURE)
	{
		MsgBox(_T("key type error"));
		goto error;
	}

	
	bRet = CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash);
	if (!bRet)
	{
		MsgBox(_T("CryptCreateHash"));
		goto error;
	}

//BYTE rgbFile[1024];
//memset(rgbFile, 0, sizeof(rgbFile));
//std::string str = "hellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohello";
//int len = str.length();
//memcpy(rgbFile, str.c_str(), len);
//char * data = W2A_(RawData);
	int RawDataLen = strlen(RawData);


	// 生成摘要
	bRet = CryptHashData(
			hHash, 
			(BYTE*)RawDataLen, 
			RawDataLen, 
			0
		);
	if (!bRet)
	{
		MsgBox(_T("CryptHashData"));
		goto error;
	}

// 对摘要进行签名
//第一次调用，得到长度

	bRet = CryptSignHash(
		hHash, 
		AT_SIGNATURE, 
		//AT_KEYEXCHANGE,
		NULL, 
		0, 
		NULL, 
		&dwSignLen
	);
	if (!bRet)
	{
		MsgBox(_T("CryptSignHash"));
		goto error;
	}
	
	pbSignature = (BYTE *)malloc(dwSignLen);

	bRet = CryptSignHash(
		hHash, 
		AT_SIGNATURE, 
		//AT_KEYEXCHANGE,
		NULL, 
		0, 
		pbSignature, 
		&dwSignLen
	);
	if (!bRet)
	{
		MsgBox(_T("CryptSignHash"));
		goto error;
	}

	// base64
	//MyB64Blob.cbData = WideCharToMultiByte( CP_THREAD_ACP, 0, pkcs10, -1, NULL, 0, NULL, NULL );
	//MyB64Blob.pbData = (BYTE*) LocalAlloc( LPTR, MyB64Blob.cbData );
	//WideCharToMultiByte( CP_THREAD_ACP, 0, pkcs10, -1, (LPSTR) MyB64Blob.pbData, MyB64Blob.cbData, NULL, NULL );
	//strResult = MyB64Blob.pbData;

	DWORD dwEncodeSize = 0;
	if (!CryptBinaryToStringA(pbSignature, dwSignLen, CRYPT_STRING_BASE64, NULL, &dwEncodeSize))
	{
		MsgBox(_T("CryptBinaryToString step 1"));
		goto error;
	}

	char* pszString = (char*) malloc(sizeof(char) * dwEncodeSize);
	if (!CryptBinaryToStringA(pbSignature, dwSignLen, CRYPT_STRING_BASE64, pszString, &dwEncodeSize))
	{
		MsgBox(_T("CryptBinaryToString step 2"));
		goto error;

	}
/*
	char * result = W2A_(pszString);
	if (result == NULL)
	{
		MsgBox(_T("W2A_"));
		goto error;
	}
*/
	strncpy(SignResult, pszString, dwEncodeSize);

//free(pbSignature);

#ifdef _DEBUG
	HANDLE hSignatureFile = NULL;
	hSignatureFile = CreateFileW(
		L"c:\\workspace_java\\verify\\data\\signresult.bin",
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	DWORD lpNumberOfBytesWritten = 0;
	bRet = WriteFile(
		hSignatureFile, 
		(LPCVOID)pbSignature, 
		dwSignLen, 
		&lpNumberOfBytesWritten, 
		NULL
	);
	if (bRet)
		MsgBox(_T("把签名结果写入文件成功"));

	CloseHandle(hSignatureFile);
#endif

error:
	if (hHash)
		CryptDestroyHash(hHash);

	if (pCertContext)
		CertFreeCertificateContext(pCertContext);

	if (hCertStore)
		CertCloseStore(hCertStore, 0);

	return bRet;
}


int __stdcall Verify()
{
	return 0;
}

int __stdcall DeleteCert(LPCTSTR DN)
{
	if (DN == NULL)
		return 0;

	PCCERT_CONTEXT   pCertContext = NULL; 
	pCertContext = SelectCertByDN(L"MY", DN);
	if (pCertContext == NULL)
		return 0;

	BOOL bRet = CertDeleteCertificateFromStore(pCertContext);
	return bRet;
}
