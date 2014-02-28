
// CertTestDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "CertTest.h"
#include "CertTestDlg.h"
#include "afxdialogex.h"

#include <wincrypt.h>
#include <cryptuiapi.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "cryptui.lib")


#include <Xenroll.h>
//#define _WIN32_DCOM 


#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

#include <string>

#include <stdio.h>
#pragma warning(disable:4996)

/*
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>  
#include <openssl/evp.h>  
#include <openssl/objects.h>  
#include <openssl/x509.h>  
#include <openssl/err.h>  
#include <openssl/pem.h>  
#include <openssl/ssl.h>  
#pragma comment(lib, "libeay32.lib")     
#pragma comment(lib, "ssleay32.lib")  
*/

#include <fstream>
#include <fstream>
#include <iostream>
#include <sstream>


#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CCertTestDlg 对话框



CCertTestDlg::CCertTestDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CCertTestDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CCertTestDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CCertTestDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_SEARCH, &CCertTestDlg::OnBnClickedSearch)
	ON_BN_CLICKED(IDC_ADD_TRUST_SITE, &CCertTestDlg::OnBnClickedAddTrustSite)
	ON_BN_CLICKED(IDC_INSTALL_ROOT, &CCertTestDlg::OnBnClickedInstallRoot)
	ON_BN_CLICKED(IDC_INSTALL_PERSONAL, &CCertTestDlg::OnBnClickedInstallPersonal)
	ON_BN_CLICKED(IDC_PKCS10, &CCertTestDlg::OnBnClickedPkcs10)
	ON_BN_CLICKED(IDC_INSTALL_SECONDCA, &CCertTestDlg::OnBnClickedInstallSecondca)
	ON_BN_CLICKED(IDC_SIGN, &CCertTestDlg::OnBnClickedSign)
	ON_BN_CLICKED(IDC_VERIFY, &CCertTestDlg::OnBnClickedVerify)
	ON_BN_CLICKED(IDC_VERIFY_OPENSSL, &CCertTestDlg::OnBnClickedVerifyOpenssl)
	ON_BN_CLICKED(IDC_FINDROOT, &CCertTestDlg::OnBnClickedFindroot)
	ON_BN_CLICKED(IDC_B64_ENCODE, &CCertTestDlg::OnBnClickedB64Encode)
END_MESSAGE_MAP()


// CCertTestDlg 消息处理程序

BOOL CCertTestDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CCertTestDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CCertTestDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CCertTestDlg::OnBnClickedSearch()
{
	// TODO: 在此添加控件通知处理程序代码
	HCERTSTORE       hCertStore;     
	PCCERT_CONTEXT   pCertContext=NULL; 
	char pszNameString[256];
	

	hCertStore = CertOpenStore(
     CERT_STORE_PROV_SYSTEM, 
     0,                      // Encoding type not needed 
                             // with this PROV.
     NULL,                   // Accept the default HCRYPTPROV. 
     CERT_SYSTEM_STORE_CURRENT_USER,
                             // Set the system store location in 
                             // the registry.
     L"MY");       

	
	// 根据证书的使用者的CN=主题来查找证书
	//LPCSTR lpszCertSubject = (LPCSTR) "63159284@64159283";
	LPCTSTR lpszCertSubject = _T("63159284@641592");

	if(pCertContext=CertFindCertificateInStore(
      hCertStore,
      MY_ENCODING_TYPE,           // Use X509_ASN_ENCODING.
      0,                          // No dwFlags needed. 
      //CERT_FIND_SUBJECT_NAME,      // Find a certificate with a
                                  // subject that matches the string
								  CERT_FIND_SUBJECT_STR,                          // in the next parameter.
      L"7315928" ,           // The Unicode string to be found
                                  // in a certificate's subject.
      NULL))                      // NULL for the first call to the
                                  // function. In all subsequent
                                  // calls, it is the last pointer
                                  // returned by the function.
	{
	  MessageBox(_T("查询证书成功\n"));
	  //pCertContext->pCertInfo->Subject.
	}
	else
	{
		TRACE(_T("查询证书失败\n"));
	}

/*
	while(pCertContext= CertEnumCertificatesInStore(
     hCertStore,
     pCertContext))
	{

			if ( CryptUIDlgViewContext(
			  CERT_STORE_CERTIFICATE_CONTEXT,
			  pCertContext,
			  NULL,
			  NULL,
			  0,
			  NULL))
			{
			//     TRACE("OK\n");
			}
			else
			{
				break;
			}

		if(CertGetNameString(
		   pCertContext,
		   CERT_NAME_SIMPLE_DISPLAY_TYPE,
		   CERT_NAME_ISSUER_FLAG,
		   NULL,
		   pszNameString,
		   128))
		{
		   TRACE("\nCertificate for %s \n",pszNameString);
		}

		DWORD            dwPropId = 0; 
void*            pvData;
DWORD            cbData;

			while(dwPropId = CertEnumCertificateContextProperties(
				pCertContext, // The context whose properties are to be listed.
				dwPropId))    // Number of the last property found.  
				// This must be zero to find the first 
				// property identifier.

			{
				switch(dwPropId)
				   {
					 case CERT_FRIENDLY_NAME_PROP_ID:
					 {
					   TRACE("Display name: ");
					   break;
					 }
					 case CERT_SIGNATURE_HASH_PROP_ID:
					 {
					   TRACE("Signature hash identifier ");
					   break;
					 }
					 case CERT_KEY_PROV_HANDLE_PROP_ID:
					 {
					   TRACE("KEY PROVE HANDLE");
					   break;
					 }
					 case CERT_KEY_PROV_INFO_PROP_ID:
					 {
					   TRACE("KEY PROV INFO PROP ID ");
					   break;
					 }
					 case CERT_SHA1_HASH_PROP_ID:
					 {
						TRACE("SHA1 HASH identifier");
						break;
					 }
					 case CERT_MD5_HASH_PROP_ID:
					 {
						TRACE("md5 hash identifier ");
						break;
					 }
					 case CERT_KEY_CONTEXT_PROP_ID:
					 {
						TRACE("KEY CONTEXT PROP identifier");
						break;
					 }
					 case CERT_KEY_SPEC_PROP_ID:
					 {
						TRACE("KEY SPEC PROP identifier");
						break;
					  }
					  case CERT_ENHKEY_USAGE_PROP_ID:
					  {
						TRACE("ENHKEY USAGE PROP identifier");
						break;
					  }
					  case CERT_NEXT_UPDATE_LOCATION_PROP_ID:
					  {
						TRACE("NEXT UPDATE LOCATION PROP identifier");
						break;
					  }
					  case CERT_PVK_FILE_PROP_ID:
					  {
						 TRACE("PVK FILE PROP identifier ");
						 break;
					  }
					  case CERT_DESCRIPTION_PROP_ID:
					  {
						TRACE("DESCRIPTION PROP identifier ");
						break;
					  }
					  case CERT_ACCESS_STATE_PROP_ID:
					  {
						TRACE("ACCESS STATE PROP identifier ");
						break;
					  }
					  case CERT_SMART_CARD_DATA_PROP_ID:
					  {
						 TRACE("SMART_CARD DATA PROP identifier ");
						 break;
					  }
					  case CERT_EFS_PROP_ID:
					  {
						TRACE("EFS PROP identifier ");
						break;
					  }
					  case CERT_FORTEZZA_DATA_PROP_ID:
					  {
						TRACE("FORTEZZA DATA PROP identifier ");
						break;
					  }
					  case CERT_ARCHIVED_PROP_ID:
					  {
						TRACE("ARCHIVED PROP identifier ");
						break;
					  }
					  case CERT_KEY_IDENTIFIER_PROP_ID:
					  {
						TRACE("KEY IDENTIFIER PROP identifier ");
						break;
					  }
					  case CERT_AUTO_ENROLL_PROP_ID:
					  {
						TRACE("AUTO ENROLL identifier. ");
						break;
					  }
				   } // End switch.
			if(CertGetCertificateContextProperty(
					 pCertContext, 
					 dwPropId , 
					 NULL, 
					 &cbData))
				{
				//  Continue.
				}

				if(pvData = (void*)malloc(cbData))
				   {
				   // Memory is allocated. Continue.
				   }
			 if(CertGetCertificateContextProperty(
				  pCertContext,
				  dwPropId,
				  pvData, 
				  &cbData))
				{
				// The data has been retrieved. Continue.
				}
			 TRACE("The Property Content is %d \n", pvData);
			 free(pvData);
			} // end while

	}//end while
	*/


	/*
	if(!(pCertContext = CryptUIDlgSelectCertificateFromStore(
	  hCertStore,
	  NULL,
	  NULL,
	  NULL,
	  CRYPTUI_SELECT_LOCATION_COLUMN,
	  0,
	  NULL)))
	{
		//MyHandleError("Select UI failed." );
	}
*/
	if(pCertContext)
	{
	   CertFreeCertificateContext(pCertContext);
	}

	if(hCertStore)
	{
		 CertCloseStore(hCertStore,0);
	}
}


void CCertTestDlg::OnBnClickedAddTrustSite()
{
	// TODO: 在此添加控件通知处理程序代码
	// http://msdn.microsoft.com/zh-cn/library/ms537143(v=vs.85).aspx

	LPCTSTR lpSubKey = _T("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\2");
	HKEY hKey;

	RegOpenKeyEx(HKEY_CURRENT_USER, lpSubKey, 0, KEY_ALL_ACCESS, &hKey);
	DWORD dwData = 67;
	RegSetValueEx(hKey, _T("Flags"), 0, REG_DWORD, (const BYTE *) &dwData, sizeof(DWORD));
	RegCloseKey(hKey);

	 ::CoInitialize(NULL);

	 HRESULT hResult = S_OK;
	 IInternetSecurityManager *pSecurityManager = NULL;

	 hResult=CoCreateInstance( CLSID_InternetSecurityManager, 
                              NULL, 
                              CLSCTX_INPROC_SERVER,
                              IID_IInternetSecurityManager,
                              (void **)&pSecurityManager );

	if (SUCCEEDED(hResult))	
    {
		hResult=pSecurityManager->SetZoneMapping(URLZONE_ESC_FLAG|URLZONE_TRUSTED,
												 L"http://*.gtja.com",
												 SZM_CREATE );

		hResult=pSecurityManager->SetZoneMapping(URLZONE_TRUSTED,
												 L"http://*.gtja.com",
												 SZM_CREATE );

		if (SUCCEEDED(hResult))
		{
			MessageBox(_T("添加信任站点成功"));
		}
		else
		{
			MessageBox(_T("添加信任站点失败"));
		}
    
      pSecurityManager->Release();
    }

	 ::CoUninitialize();
}







void CCertTestDlg::OnBnClickedInstallRoot()
{
	// TODO: 在此添加控件通知处理程序代码
	char * CertFile = "C:\\Program Files\\CsswebCert\\rootca.cer";
	std::wstringstream wss;
	wss << CertFile;
	const wchar_t* pwCertFile = wss.str().c_str();
	const wchar_t* wCertFile = GetWC(CertFile);

	InstallCert(L"ROOT", wCertFile);

/*
//http://msdn.microsoft.com/en-us/library/windows/desktop/aa388136(v=vs.85).aspx

	DWORD dwMsgAndCertEncodingType;
	DWORD dwContentType;
	DWORD dwFormatType;
	PCCERT_CONTEXT pCertCtx = NULL;
	HCERTSTORE       hCertStore;     

	//http://msdn.microsoft.com/en-us/library/windows/desktop/aa380264(v=vs.85).aspx
	BOOL bRet = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
		L"C:\\Program Files\\CsswebCert\\rootca.cer",
		//L"C:\\workspace_cpp\\Certificate\\bin\\rootca.cer",
		CERT_QUERY_CONTENT_FLAG_ALL,
		CERT_QUERY_FORMAT_FLAG_ALL,
		0,
		&dwMsgAndCertEncodingType,
		&dwContentType,
		&dwFormatType,
		NULL,
		NULL, 
		(const void **)&pCertCtx);
	if (!bRet)
	{
		MessageBox("读证书文件失败");
		return;
	}





//http://msdn.microsoft.com/en-us/library/windows/desktop/aa376559(v=vs.85).aspx

	hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
		0,
		NULL,
		CERT_SYSTEM_STORE_CURRENT_USER,
		L"ROOT");
	if (hCertStore == NULL)
	{
		MessageBox("打开证书库失败");
		return;
	}



	//http://msdn.microsoft.com/zh-cn/library/windows/desktop/aa376009(v=vs.85).aspx
	//CryptUIWizImport
	bRet = CertAddCertificateContextToStore(hCertStore, pCertCtx, CERT_STORE_ADD_ALWAYS, NULL);
	if (bRet)
	{
		MessageBox("导入根证书成功\n");
	}
	else
	{
		MessageBox("导入根证书失败\n");
	}

	if (pCertCtx)
    {
        CertFreeCertificateContext (pCertCtx);
    }

	CertCloseStore(hCertStore, 0);
*/
}

void CCertTestDlg::OnBnClickedInstallSecondca()
{
	// TODO: 在此添加控件通知处理程序代码
	DWORD dwMsgAndCertEncodingType;
	DWORD dwContentType;
	DWORD dwFormatType;
	PCCERT_CONTEXT pCertCtx = NULL;
	HCERTSTORE       hCertStore;     

	//http://msdn.microsoft.com/en-us/library/windows/desktop/aa380264(v=vs.85).aspx
	BOOL bRet = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
		L"operation.cer",
		//L"D:\\product\\Server\\CertServer\\taobao_personal_test.cer",
		CERT_QUERY_CONTENT_FLAG_ALL,
		CERT_QUERY_FORMAT_FLAG_ALL,
		0,
		&dwMsgAndCertEncodingType,
		&dwContentType,
		&dwFormatType,
		NULL,
		NULL, 
		(const void **)&pCertCtx);
	if (!bRet)
	{
		MessageBox(_T("读证书文件失败"));
		return;
	}



//http://msdn.microsoft.com/en-us/library/windows/desktop/aa376559(v=vs.85).aspx

	/*MY
Root
Trust
CA
*/
	hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
		0,
		NULL,
		CERT_SYSTEM_STORE_CURRENT_USER,
		L"CA");
	if (hCertStore == NULL)
	{
		MessageBox(_T("打开证书库失败"));
		return;
	}


	//http://msdn.microsoft.com/zh-cn/library/windows/desktop/aa376009(v=vs.85).aspx
	//CryptUIWizImport
	bRet = CertAddCertificateContextToStore(hCertStore, pCertCtx, CERT_STORE_ADD_ALWAYS, NULL);
	if (bRet)
	{
		MessageBox(_T("导入证书成功\n"));
	}
	else
	{
		MessageBox(_T("导入证书失败\n"));
	}

	if (pCertCtx)
    {
        CertFreeCertificateContext (pCertCtx);
    }

	CertCloseStore(hCertStore, 0);

}

void CCertTestDlg::OnBnClickedInstallPersonal()
{
	// TODO: 在此添加控件通知处理程序代码
	BOOL bRet = FALSE;
	DWORD dwMsgAndCertEncodingType;
	DWORD dwContentType;
	DWORD dwFormatType;
	PCCERT_CONTEXT pCertCtx = NULL;
	HCERTSTORE       hCertStore = NULL; 

	char* Cert = "MIIDKTCCAhGgAwIBAgIEKrEBwTANBgkqhkiG9w0BAQUFADA/MQswCQYDVQQGEwJDTjESMBAGA1UECgwJQ1NEQyBUZXN0MRwwGgYDVQQDDBNPcGVyYXRpb24gQ0EwMSBUZXN0MB4XDTEzMDUwODA4MDU1MVoXDTE0MDUwODA4MDU1MVowTzELMAkGA1UEBhMCQ04xEjAQBgNVBAoMCUNTREMgVGVzdDEUMBIGA1UECwwLQ3VzdG9tZXJzMDExFjAUBgNVBAMMDUNAMUAxMDAwMDM4NDEwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAK0JwEMVSyys9iBJRSwD06N4VelYukDkoB8EtnGEBT2oVIRn17Y/zac58dbHJB8Ua61Vz3lQ6inS1Hqf49eAFgUYX1MWwxkeBn/tIPR0L7Gn3+sOQY7e6/zGf+53uX3w5h0VO3oOK3uV72hgp3/z2uUJr1wqEkKbXTeaK7sL+5ntAgMBAAGjgaAwgZ0wEQYJYIZIAYb4QgEBBAQDAgWgMAkGA1UdEwQCMAAwUQYDVR0fBEowSDBGoESgQqRAMD4xCzAJBgNVBAYTAkNOMRIwEAYDVQQKDAlDU0RDIFRlc3QxDDAKBgNVBAsMA2NybDENMAsGA1UEAwwEY3JsMTALBgNVHQ8EBAMCBsAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMA0GCSqGSIb3DQEBBQUAA4IBAQCCn9/8ZrreKU2pPnYEFOfPElfD2k5ia3gdMK2p+8ln5AkSfgPDeNRLb3LpjuMkE5IjAjTsARWbTCm1AM6hwWQk1ol91dALXXFHrKOrjZITKXDOpL1EMmXrJvrlYsm+eTgBmDyGLU1gxrimO5SIEZRIpFAOBtw/89VSm8fTANO4Tgp+hGAX8DGb+pZdIniIsEbzbnjZI50uQMf+FagxYgBGuts0c7tqHY2wW3p0Cm9Ok0AuuG5+6TWET30ypOZSnfc9uXwL/0k9USjxKIBcod+GTj0ePmwIOOzuPG/arLr7aTi9lEw3Nm6M53nOWbDK6fP472RrQmKERGHA1pq6qwmj";
	size_t len = strlen(Cert);

	CERT_BLOB certBlob = {0, NULL};
	certBlob.cbData = len;
	certBlob.pbData = (BYTE*) malloc(len+1);
	memcpy(certBlob.pbData, Cert, len);
	certBlob.pbData[len] = '\0';

	DWORD dwCertEncoded = 0;
	DWORD dwSkip, dwFlags;
	if (!CryptStringToBinaryA(Cert, len, CRYPT_STRING_BASE64, NULL, &dwCertEncoded, &dwSkip, &dwFlags))
	{
	

	}

	BYTE* pbCertEncoded = (BYTE*) malloc(dwCertEncoded);
	if (!CryptStringToBinaryA(Cert, len, CRYPT_STRING_BASE64, pbCertEncoded, &dwCertEncoded, &dwSkip, &dwFlags))
	{

	}


	

	pCertCtx = CertCreateCertificateContext(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, pbCertEncoded, dwCertEncoded);
	if (pCertCtx == NULL)
	{
		TRACE("解析证书出错\n");
		return;
	}

	CRYPTUI_WIZ_IMPORT_SRC_INFO s;
	memset(&s, 0, sizeof(CRYPTUI_WIZ_IMPORT_SRC_INFO));
	s.dwSize = sizeof(CRYPTUI_WIZ_IMPORT_SRC_INFO);
	s.dwSubjectChoice = CRYPTUI_WIZ_IMPORT_SUBJECT_CERT_CONTEXT;
	s.pCertContext = pCertCtx;
	s.dwFlags = CRYPT_EXPORTABLE;

	bRet = CryptUIWizImport(CRYPTUI_WIZ_NO_UI, NULL, NULL, &s, NULL);
	if (bRet == TRUE)
	{
		TRACE("import success\n");
	}
	else
	{
		TRACE("import error\n");
	}
/*
	BOOL bRet = CryptQueryObject(CERT_QUERY_OBJECT_BLOB,
		 &certBlob,
		//L"D:\\product\\Server\\CertServer\\taobao_personal_test.cer",
		CERT_QUERY_CONTENT_FLAG_CERT,
		CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED,
		0,
		&dwMsgAndCertEncodingType,
		&dwContentType,
		&dwFormatType,
	//	&hCertStore,
	NULL,
		NULL, 
		(const void **)&pCertCtx);

	if (bRet)
	{
		TRACE("query success\n");
	}
	else
	{
		TRACE("query fail\n");
		return ;
	}
*/	
/*
	hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
		0,
		NULL,
		CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG,
		L"MY");
	if (hCertStore == NULL)
	{
		return ;
	}

	bRet = CertAddCertificateContextToStore(hCertStore, pCertCtx, CERT_STORE_ADD_NEW, NULL);
	if (bRet)
	{
		TRACE("install success new\n");
	}
	else
	{
		TRACE("install error new\n");
	}
*/
/*
	bRet = CertAddCertificateContextToStore(hCertStore, pCertCtx, CERT_STORE_ADD_REPLACE_EXISTING, NULL);
	if (bRet)
	{
		TRACE("install success rep\n");
	}
	else
	{
		TRACE("install error rep\n");
	}
*/
	if (pCertCtx)
    {
       // CertFreeCertificateContext (pCertCtx);
    }

	if (hCertStore)
		CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);

	//return bRet;
}

void CCertTestDlg::OnBnClickedPkcs10()
{
	// TODO: 在此添加控件通知处理程序代码
	HRESULT				hr;
	CRYPT_DATA_BLOB		MyB64Blob = { 0, NULL };
	CRYPT_DATA_BLOB		MyBlob = { 0, NULL };
	
	LPWSTR				OutputString = NULL;

	IEnroll4*			CertEnroll = NULL;
	 ICEnroll4 * pEnroll = NULL;
	 
	 std::ofstream myfile("pkcs10.txt");


	hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	 //hr = ::CoInitialize(NULL);
	if (FAILED(hr))
	{
		TRACE("error\n");
		goto error;
	}

	
	hr = CoCreateInstance(CLSID_CEnroll,NULL,CLSCTX_INPROC_SERVER,IID_IEnroll4,(void **)&CertEnroll);
	//hr = CoCreateInstance(CLSID_CEnroll,NULL,CLSCTX_INPROC_SERVER,IID_ICEnroll4,(void **)&pEnroll);
	if (FAILED(hr))
	{
		TRACE( L"CoCreateInstance failed: 0x%x\n", hr);
		MessageBox(_T("CoCreateInstance error"));
		goto error;

	}

	LPCWSTR	wszCSPName		= L"Microsoft Enhanced Cryptographic Provider v1.0";
	hr = CertEnroll->put_ProviderNameWStr((LPWSTR)wszCSPName);
	if (FAILED(hr))
	{
	
		MessageBox(_T("put_ProviderNameWStr error"));
		goto error;
	}

	DWORD	dwKeySpec		= AT_SIGNATURE;
	// Key specification either AT_KEYEXCHANGE / AT_SIGNATURE
	hr=CertEnroll->put_KeySpec( dwKeySpec );
    if(FAILED(hr))
	{
		
		MessageBox(_T("put_KeySpec error"));
		goto error;
	}

	LPCWSTR	wszTemplateName	= L"EFS";
	// ClientAuth
	hr = CertEnroll->AddCertTypeToRequestWStr((LPWSTR)wszTemplateName);
	if (FAILED(hr))
	{
		MessageBox(_T("AddCertTypeToRequestWStr error"));
		goto error;
	}
	
	DWORD	dwProviderType	= PROV_RSA_FULL;
	hr=CertEnroll->put_ProviderType( dwProviderType );
    if(FAILED(hr))
	{
		
		MessageBox(_T("put_ProviderType error"));
		goto error;
	}

	hr=CertEnroll->put_KeySpec( dwKeySpec );
    if(FAILED(hr))
	{
		
		MessageBox(_T("put_KeySpec error"));
		goto error;
	}

	DWORD	dwKeyLength		= 1024;
	DWORD	dwGenKeyFlags	= ( dwKeyLength << 16 ) | CRYPT_EXPORTABLE;
	hr=CertEnroll->put_GenKeyFlags( dwGenKeyFlags );
    if(FAILED(hr))
	{

		MessageBox(_T("put_GenKeyFlags error"));
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
		MessageBox(_T("createRequestWStr error"));
		goto error;
	}

	
	hr=CertEnroll->binaryBlobToString( CRYPT_STRING_BASE64REQUESTHEADER, &MyBlob, &OutputString );
    if(FAILED(hr))
	{
		MessageBox(_T("binaryBlobToString error"));
		goto error;
	}

	
	MyB64Blob.cbData = WideCharToMultiByte( CP_THREAD_ACP, 0, OutputString, -1, NULL, 0, NULL, NULL );
	MyB64Blob.pbData = (BYTE*) LocalAlloc( LPTR, MyB64Blob.cbData );
	WideCharToMultiByte( CP_THREAD_ACP, 0, OutputString, -1, (LPSTR) MyB64Blob.pbData, MyB64Blob.cbData, NULL, NULL );

	
	USES_CONVERSION;
	char * b64 = W2A(OutputString);

	hr = 0;

	if (myfile.is_open())
  {
    myfile << b64;
	MessageBox(_T("申请成功"));

    myfile.close();
  }


error:
	if ( NULL != MyB64Blob.pbData )
		LocalFree( MyB64Blob.pbData );
	
	if ( NULL != CertEnroll )
		CertEnroll->Release();

	if ( NULL != MyBlob.pbData )
	    LocalFree( MyBlob.pbData );

	if ( NULL != OutputString )
		LocalFree( OutputString );

	CoUninitialize();
}




void CCertTestDlg::OnBnClickedSign()
{
	// TODO: 在此添加控件通知处理程序代码
	BOOL bRet = FALSE;

	HCERTSTORE       hCertStore;    
		hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
		0,
		NULL,
		CERT_SYSTEM_STORE_CURRENT_USER,
		L"MY");

	if (hCertStore == NULL)
	{
		TRACE("CertOpenStore");
		return;
	}

	PCCERT_CONTEXT   pCertContext=NULL; 
	LPCTSTR lpszCertSubject = _T("C@1@100004121");

	if(pCertContext=CertFindCertificateInStore(
      hCertStore,
      MY_ENCODING_TYPE,           // Use X509_ASN_ENCODING.
      0,                          // No dwFlags needed. 
      //CERT_FIND_SUBJECT_NAME,      // Find a certificate with a
                                  // subject that matches the string
								  CERT_FIND_SUBJECT_STR,                          // in the next parameter.
      lpszCertSubject ,           // The Unicode string to be found
                                  // in a certificate's subject.
      NULL))                      // NULL for the first call to the
                                  // function. In all subsequent
                                  // calls, it is the last pointer
                                  // returned by the function.
	{
	  TRACE("The desired certificate was found. \n");
	  //pCertContext->pCertInfo->Subject.
	}
	else
	{
		TRACE("not found\n");
		return;
	}

	HCRYPTPROV hCryptProv = NULL;
	DWORD dwKeySpec = 0;
	bRet = CryptAcquireCertificatePrivateKey(
			pCertContext,
			0,
			NULL,
			&hCryptProv,
			&dwKeySpec,
			NULL
		);

	int t = dwKeySpec & AT_SIGNATURE;
	if (t != AT_SIGNATURE)
	{
		TRACE("key type error\n");
		return;
	}

	HCRYPTHASH hHash = NULL;
bRet = CryptCreateHash(
		hCryptProv, 
		CALG_MD5, 
		0, 
		0, 
		&hHash
	);


//LPCTSTR RawData = _T("测试hellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohello");
LPCTSTR RawData = _T("测试123");
char * data = W2A_(RawData);
int RawDataLen = strlen(data);
// 生成摘要
bRet = CryptHashData(
			hHash, 
			(const BYTE*)data, 
			RawDataLen, 
			0
		);

/*
int RawDataLen = _tcslen(RawData);
// 生成摘要
bRet = CryptHashData(
			hHash, 
			(const BYTE*)RawData, 
			RawDataLen, 
			0
		);
*/

// 对摘要进行签名
//第一次调用，得到长度
DWORD dwSignLen;

	bRet = CryptSignHash(
		hHash, 
		AT_SIGNATURE, 
		//AT_KEYEXCHANGE,
		NULL, 
		0, 
		NULL, 
		&dwSignLen
	);
	//用私钥签名
	
	pbSignature = (BYTE *)malloc(dwSignLen);
bRet = CryptSignHash(
		hHash, 
		AT_SIGNATURE, 
		//AT_KEYEXCHANGE,
		NULL, 
		0, 
		pbSignature, 
		&dwSigLen
	);

	DWORD dwEncodeSize = 0;
	if (!CryptBinaryToStringA(pbSignature, dwSignLen, CRYPT_STRING_BASE64, NULL, &dwEncodeSize))
	{
		
		return;
	}

	char* pszString = (char*) malloc(sizeof(char) * dwEncodeSize);
	if (!CryptBinaryToStringA(pbSignature, dwSignLen, CRYPT_STRING_BASE64, pszString, &dwEncodeSize))
	{
		
		return;

	}

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
		(LPCVOID)pszString, 
		dwEncodeSize, 
		&lpNumberOfBytesWritten, 
		NULL
	);
	if (bRet)
	{
		TRACE("sign success\n");
	}

	CloseHandle(hSignatureFile);

	if (hHash)
		CryptDestroyHash(hHash);

	if (pCertContext)
		CertFreeCertificateContext(pCertContext);

	if (hCertStore)
		CertCloseStore(hCertStore, 0);
}


void CCertTestDlg::OnBnClickedVerify()
{
	// TODO: 在此添加控件通知处理程序代码
	BOOL bRet;

	HCERTSTORE       hCertStore;  
	hCertStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,
		0,
		NULL,
		CERT_SYSTEM_STORE_CURRENT_USER,
		L"MY"	
	);

		PCCERT_CONTEXT   pCertContext=NULL; 
	LPCSTR lpszCertSubject = (LPCSTR) "C@1@100001060";

	pCertContext = CertFindCertificateInStore(
		hCertStore,
		MY_ENCODING_TYPE,
		0,
		CERT_FIND_SUBJECT_STR_A,
		lpszCertSubject,
		NULL
	);
	if (pCertContext == NULL)
	{
		TRACE("not found\n");
	}
	else
	{
	}

	HCRYPTPROV hCryptProv = NULL;
	bRet = CryptAcquireContext(
			&hCryptProv,
			NULL,
			NULL,
			PROV_RSA_FULL,
			CRYPT_VERIFYCONTEXT
		);

	HCRYPTHASH hHash = NULL;
	bRet = CryptCreateHash(
			hCryptProv, 
			CALG_MD5, 
			0, 
			0, 
			&hHash
		);

	// 对原文生成摘要
	BYTE rgbFile[1024];
	memset(rgbFile, 0, sizeof(rgbFile));
	std::string str = "hellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohello";
	int len = str.length();
	memcpy(rgbFile, str.c_str(), len);


	bRet = CryptHashData(
				hHash, 
				rgbFile, 
				len, 
				0
			);

	HCRYPTKEY hPubKey = NULL;
	bRet = CryptImportPublicKeyInfo(
			hCryptProv, 
			MY_ENCODING_TYPE,
			&pCertContext->pCertInfo->SubjectPublicKeyInfo,
			&hPubKey
		);

	bRet = CryptVerifySignature(
			hHash, 
			pbSignature, 
			dwSigLen, 
			hPubKey,
			NULL, 
			0
		);
	if (bRet)
	{
		TRACE("验签成功\n");
	}
	else
	{
		TRACE("验签失败\n");
	}

	free(pbSignature);

	CryptDestroyHash(hHash);

	CertFreeCertificateContext(pCertContext);

	CertCloseStore(
		hCertStore, 
		0
	);

	 CryptReleaseContext(
		hCryptProv,
		0
	);
}

void CCertTestDlg::OnBnClickedVerifyOpenssl()
{
	// TODO: 在此添加控件通知处理程序代码
/*
	ERR_load_crypto_strings();  

	FILE* fp = fopen ("D:\\workspace\\PKIVerifySign\\src\\100001060.cer", "r");
	if (fp == NULL)
		return;

	X509* x509 = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);

	if (x509 == NULL)
	{
		return;
	}

	EVP_PKEY * pkey = X509_get_pubkey(x509);
	if (pkey == NULL)
	{
	}

	EVP_MD_CTX md_ctx;  
	EVP_MD_CTX_init(&md_ctx);  

	int nRet = 0;

	nRet = EVP_VerifyInit(&md_ctx, EVP_md5());

	std::string str = "hellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohello";
	nRet = EVP_VerifyUpdate(&md_ctx, str.c_str(), str.length());  
	

	std::ifstream inFile;
	inFile.open("D:\\workspace\\PKIVerifySign\\src\\signresult.bin", std::ios::in | std::ios::binary | std::ios::ate);
	size_t len = 0;
	char* signData = NULL;
	if (inFile.is_open())
	{
		inFile.seekg(0, std::ios::end);
		len = inFile.tellg();

		inFile.seekg(0, std::ios::beg);

		signData = new char[len+1];
		inFile.read(signData, len);
		signData[len] = '\0';

		inFile.close();
	}

			for (int i = 0; i < len / 2; i++) {
				char temp = signData[i];
				signData[i] = signData[len - i - 1];
				signData[len - i - 1] = temp;
			}

	nRet = EVP_VerifyFinal(&md_ctx, (const unsigned char*)signData, len, pkey);  
	if (signData != NULL)
		delete[] signData;

	EVP_PKEY_free (pkey);  
	EVP_MD_CTX_cleanup(&md_ctx);  
*/
}
const wchar_t * CCertTestDlg::GetWC(const char *c)
{
    const size_t cSize = strlen(c)+1;
    wchar_t* wc = new wchar_t[cSize];
    mbstowcs (wc, c, cSize);

    return wc;
}
BOOL CCertTestDlg::InstallCert(const wchar_t* Store, const wchar_t* CertFile)
{
	DWORD dwMsgAndCertEncodingType;
	DWORD dwContentType;
	DWORD dwFormatType;
	PCCERT_CONTEXT pCertCtx = NULL;
	HCERTSTORE hCertStore = NULL;     

	BOOL bResult = FALSE;

	
	bResult = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
		CertFile,
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
		Store);

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


void CCertTestDlg::OnBnClickedFindroot()
{
	// TODO: 在此添加控件通知处理程序代码
	
PCCERT_CONTEXT   pCertContext = NULL; 
	pCertContext = SelectCertByDN("ROOT", "C=CN, O=CSDC Test, CN=Root CA Test");

	//pCertContext = SelectCertByDN("CA", "C=CN, O=CSDC Test, CN=Operation CA01 Test");
	
	if (pCertContext == NULL)
		TRACE("root cert is not exist");
	else
		TRACE("root cert found");
}

PCCERT_CONTEXT CCertTestDlg::SelectCertByDN(char * Store, char* pDN)
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
     L"ROOT");  

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
/*
		char* pszString;
		if (!(pszString = (char*) malloc(cbSize * sizeof(char))) )
		{
		}

		cbSize = CertNameToStr(pCertContext->dwCertEncodingType,
			&(pCertContext->pCertInfo->Subject),
			CERT_X500_NAME_STR,
			pszString,
			cbSize);

		TRACE("ca cert dn %s\n", pszString);
*/
		if(pCertContext)
		{
	//		CertFreeCertificateContext(pCertContext);
		}

	
/*
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
*/
	} // end while


	if(hCertStore)
	{
		CertCloseStore(hCertStore, 0);
	}

	return NULL;
}
char *  CCertTestDlg::W2A_(const wchar_t * lpwStr)
{
/*
int WideCharToMultiByte(
  _In_       UINT CodePage,
  _In_       DWORD dwFlags,
  _In_       LPCWSTR lpWideCharStr,
  _In_       int cchWideChar,
  _Out_opt_  LPSTR lpMultiByteStr,
  _In_       int cbMultiByte,
  _In_opt_   LPCSTR lpDefaultChar,
  _Out_opt_  LPBOOL lpUsedDefaultChar
);
*/
	if (lpwStr == NULL)
		return NULL;

	int len1 = WideCharToMultiByte(CP_ACP, 0, lpwStr, -1, NULL, 0, NULL, NULL);
	TRACE("len1 = %d\n", len1);

	char * str = new char[len1+1];
	int len2 = WideCharToMultiByte(CP_ACP, 0 ,lpwStr, -1 , str, len1, NULL, NULL); 
	str[len2] = '\0';
	TRACE("len2 = %d\n", len2);

	return str;
}

wchar_t *  CCertTestDlg::A2W_(const char * lpStr)
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
	TRACE("len1 = %d\n", len1);

	//wchar_t* pwstr = new wchar_t[len1];
	wchar_t* pwstr = new wchar_t[len1 + 1];
	int len2 = MultiByteToWideChar(CP_ACP, 0, lpStr, -1, pwstr, len1); 
	pwstr[len2] = '\0';
	TRACE("len2 = %d\n", len2);
	
	
	return pwstr;
}

void CCertTestDlg::OnBnClickedB64Encode()
{
	// TODO: 在此添加控件通知处理程序代码
	LPCTSTR rawdata = _T("测试123");

	//BYTE* pbRawData = (BYTE*)W2A_(rawdata);
	//DWORD dwRawData = strlen((const char*)pbRawData);
	DWORD dwRawData = _tcslen(rawdata);
	DWORD dwEncodeSize = 0;
	if (!CryptBinaryToString((BYTE*)rawdata, dwRawData, CRYPT_STRING_BASE64, NULL, &dwEncodeSize))
	{

	}

	LPWSTR pszString = (LPWSTR) malloc(sizeof(TCHAR) * dwEncodeSize);
	if (!CryptBinaryToString((BYTE*)rawdata, dwRawData, CRYPT_STRING_BASE64, pszString, &dwEncodeSize))
	{
	}
	char * result = W2A_(pszString);
	TRACE("base64 encode: %s\n", result);
}
