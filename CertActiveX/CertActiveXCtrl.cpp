// CertActiveXCtrl.cpp : CCertActiveXCtrl ActiveX 控件类的实现。

#include "stdafx.h"
#include "CertActiveX.h"
#include "CertActiveXCtrl.h"
#include "CertActiveXPropPage.h"
#include "afxdialogex.h"

#include <wincrypt.h>
#include <cryptuiapi.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "cryptui.lib")

#include <Xenroll.h>

#include <vector>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


IMPLEMENT_DYNCREATE(CCertActiveXCtrl, COleControl)



// 消息映射

BEGIN_MESSAGE_MAP(CCertActiveXCtrl, COleControl)
	ON_OLEVERB(AFX_IDS_VERB_PROPERTIES, OnProperties)
END_MESSAGE_MAP()



// 调度映射

BEGIN_DISPATCH_MAP(CCertActiveXCtrl, COleControl)

	DISP_FUNCTION_ID(CCertActiveXCtrl, "FindCertByDN", dispidFindCertByDN, FindCertByDN, VT_I2, VTS_BSTR)
	DISP_FUNCTION_ID(CCertActiveXCtrl, "CreateCSR", dispidCreateCSR, CreateCSR, VT_BSTR, VTS_NONE)
	DISP_FUNCTION_ID(CCertActiveXCtrl, "InstallCert", dispidInstallCert, InstallCert, VT_I2, VTS_BSTR)

	DISP_FUNCTION_ID(CCertActiveXCtrl, "Sign", dispidSign, Sign, VT_BSTR, VTS_BSTR VTS_BSTR)
	DISP_FUNCTION_ID(CCertActiveXCtrl, "Verify", dispidVerify, Verify, VT_I2, VTS_BSTR VTS_BSTR VTS_BSTR)
	DISP_FUNCTION_ID(CCertActiveXCtrl, "DeleteCert", dispidDeleteCert, DeleteCert, VT_I2, VTS_BSTR)
	DISP_FUNCTION_ID(CCertActiveXCtrl, "ConvertDN", dispidConvertDN, ConvertDN, VT_BSTR, VTS_BSTR)
END_DISPATCH_MAP()



// 事件映射

BEGIN_EVENT_MAP(CCertActiveXCtrl, COleControl)
END_EVENT_MAP()



// 属性页

// TODO: 按需要添加更多属性页。请记住增加计数!
BEGIN_PROPPAGEIDS(CCertActiveXCtrl, 1)
	PROPPAGEID(CCertActiveXPropPage::guid)
END_PROPPAGEIDS(CCertActiveXCtrl)



// 初始化类工厂和 guid

IMPLEMENT_OLECREATE_EX(CCertActiveXCtrl, "CERTACTIVEX.CertActiveXCtrl.1",
	0x24465789, 0x5bd9, 0x435c, 0x85, 0xaf, 0x8b, 0x90, 0xd7, 0xca, 0x89, 0x56)



// 键入库 ID 和版本

IMPLEMENT_OLETYPELIB(CCertActiveXCtrl, _tlid, _wVerMajor, _wVerMinor)



// 接口 ID

const IID IID_DCertActiveX = { 0x54581409, 0x9C25, 0x48DB, { 0x82, 0x7, 0x7D, 0xB, 0xD2, 0x4D, 0x27, 0x35 } };
const IID IID_DCertActiveXEvents = { 0x2C64E849, 0xD2B1, 0x423B, { 0xA0, 0x96, 0x2E, 0xE9, 0x8E, 0xB7, 0xB, 0xA1 } };


// 控件类型信息

static const DWORD _dwCertActiveXOleMisc =
	OLEMISC_INVISIBLEATRUNTIME |
	OLEMISC_SETCLIENTSITEFIRST |
	OLEMISC_INSIDEOUT |
	OLEMISC_CANTLINKINSIDE |
	OLEMISC_RECOMPOSEONRESIZE;

IMPLEMENT_OLECTLTYPE(CCertActiveXCtrl, IDS_CERTACTIVEX, _dwCertActiveXOleMisc)



// CCertActiveXCtrl::CCertActiveXCtrlFactory::UpdateRegistry -
// 添加或移除 CCertActiveXCtrl 的系统注册表项

BOOL CCertActiveXCtrl::CCertActiveXCtrlFactory::UpdateRegistry(BOOL bRegister)
{
	// TODO: 验证您的控件是否符合单元模型线程处理规则。
	// 有关更多信息，请参考 MFC 技术说明 64。
	// 如果您的控件不符合单元模型规则，则
	// 必须修改如下代码，将第六个参数从
	// afxRegApartmentThreading 改为 0。

	if (bRegister)
		return AfxOleRegisterControlClass(
			AfxGetInstanceHandle(),
			m_clsid,
			m_lpszProgID,
			IDS_CERTACTIVEX,
			IDB_CERTACTIVEX,
			afxRegApartmentThreading,
			_dwCertActiveXOleMisc,
			_tlid,
			_wVerMajor,
			_wVerMinor);
	else
		return AfxOleUnregisterClass(m_clsid, m_lpszProgID);
}



// CCertActiveXCtrl::CCertActiveXCtrl - 构造函数

CCertActiveXCtrl::CCertActiveXCtrl()
{
	InitializeIIDs(&IID_DCertActiveX, &IID_DCertActiveXEvents);
	// TODO: 在此初始化控件的实例数据。
}



// CCertActiveXCtrl::~CCertActiveXCtrl - 析构函数

CCertActiveXCtrl::~CCertActiveXCtrl()
{
	// TODO: 在此清理控件的实例数据。
}



// CCertActiveXCtrl::OnDraw - 绘图函数

void CCertActiveXCtrl::OnDraw(
			CDC* pdc, const CRect& rcBounds, const CRect& rcInvalid)
{
	if (!pdc)
		return;

	// TODO: 用您自己的绘图代码替换下面的代码。
	pdc->FillRect(rcBounds, CBrush::FromHandle((HBRUSH)GetStockObject(WHITE_BRUSH)));
	pdc->Ellipse(rcBounds);
}



// CCertActiveXCtrl::DoPropExchange - 持久性支持

void CCertActiveXCtrl::DoPropExchange(CPropExchange* pPX)
{
	ExchangeVersion(pPX, MAKELONG(_wVerMinor, _wVerMajor));
	COleControl::DoPropExchange(pPX);

	// TODO: 为每个持久的自定义属性调用 PX_ 函数。
}



// CCertActiveXCtrl::OnResetState - 将控件重置为默认状态

void CCertActiveXCtrl::OnResetState()
{
	COleControl::OnResetState();  // 重置 DoPropExchange 中找到的默认值

	// TODO: 在此重置任意其他控件状态。
}



// ok
//LPCSTR lpszCertSubject = (LPCSTR) "C=CN, O=CSDC Test, OU=Access, CN=63159284@64159283";
SHORT CCertActiveXCtrl::FindCertByDN(LPCTSTR DN)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());

	// TODO: 在此添加调度处理程序代码
	PCCERT_CONTEXT   pCertContext = NULL; 
	pCertContext = this->SelectCertByDN(DN);
	if (pCertContext == NULL)
		return 0;

	return 1;
}

// ok
BSTR CCertActiveXCtrl::CreateCSR(void)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());

	CString strResult;

	// TODO: 在此添加调度处理程序代码
	strResult = "";

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

	LPWSTR	wszCSPName		= _T("Microsoft Enhanced Cryptographic Provider v1.0");
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

	LPWSTR	wszTemplateName	= _T("EFS");
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

	strResult = MyB64Blob.pbData;

//	USES_CONVERSION;
//	char * b64 = W2A(OutputString);

	hr = 0;

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

	

	return strResult.AllocSysString();
}

// ok
SHORT CCertActiveXCtrl::InstallCert(LPCTSTR Cert)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());

	// TODO: 在此添加调度处理程序代码
	if (Cert == NULL)
		return 0;

	DWORD dwMsgAndCertEncodingType;
	DWORD dwContentType;
	DWORD dwFormatType;
	PCCERT_CONTEXT pCertCtx = NULL;
	HCERTSTORE       hCertStore = NULL; 

	char* lpCert = W2A_(Cert);
	size_t len = strlen(lpCert);

	DWORD dwCertEncoded = 0;
	DWORD dwSkip, dwFlags;
	if (!CryptStringToBinaryA(lpCert, len, CRYPT_STRING_BASE64, NULL, &dwCertEncoded, &dwSkip, &dwFlags))
	{
	
		MsgBox(_T("CryptStringToBinaryA 1"));
		return 0;
	}

	BYTE* pbCertEncoded = (BYTE*) malloc(dwCertEncoded);
	if (!CryptStringToBinaryA(lpCert, len, CRYPT_STRING_BASE64, pbCertEncoded, &dwCertEncoded, &dwSkip, &dwFlags))
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




//
// 很长数据的签名，应该改成循环形式
BSTR CCertActiveXCtrl::Sign(LPCTSTR CertDN, LPCTSTR RawData)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());

	CString strResult;
	strResult = "";

	// TODO: 在此添加调度处理程序代码
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

	if(pCertContext=SelectCertByDN(CertDN))
	{
	  TRACE("The desired certificate was found. \n");
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
char * data = W2A_(RawData);
int RawDataLen = strlen(data);


	// 生成摘要
	bRet = CryptHashData(
			hHash, 
			(BYTE*)data, 
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
	strResult = pszString;

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

	return strResult.AllocSysString();
}


SHORT CCertActiveXCtrl::Verify(LPCTSTR CertDN, LPCTSTR RawData, LPCTSTR SignResult)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());

	// TODO: 在此添加调度处理程序代码
	BOOL bRet = FALSE;

	MessageBox(_T("暂时仅提供测试，不要使用"));
	return bRet;

	HCERTSTORE       hCertStore = NULL;
	PCCERT_CONTEXT   pCertContext=NULL; 
	HCRYPTPROV hCryptProv = NULL;
	HCRYPTHASH hHash = NULL;
	HCRYPTKEY hPubKey = NULL;
	

	if (CertDN == NULL)
		return 0;

	if (RawData == NULL)
		return 0;

	if (SignResult == NULL)
		return 0;

	DWORD dwSignLen = _tcslen(SignResult);

	DWORD cbSignLen = 0;
	DWORD dwSkip, dwFlags;
	if (!CryptStringToBinary(SignResult, dwSignLen, CRYPT_STRING_BASE64, NULL, &cbSignLen, &dwSkip, &dwFlags))
	{
		MsgBox(_T("CryptStringToBinary step 1"));
		goto error;

	}

	BYTE* pbSignature = (BYTE*) malloc(cbSignLen);
	if (!CryptStringToBinary(SignResult, dwSignLen, CRYPT_STRING_BASE64, pbSignature, &cbSignLen, &dwSkip, &dwFlags))
	{
		MsgBox(_T("CryptStringToBinary step 2"));
		goto error;

	}
	

	hCertStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,
		0,
		NULL,
		CERT_SYSTEM_STORE_CURRENT_USER,
		_T("MY")	
	);
	if (hCertStore == NULL)
	{
		MsgBox(_T("CertOpenStore"));
		goto error;
	}

		
//	LPCSTR lpszCertSubject = (LPCSTR) "C@1@100001060";

	pCertContext = SelectCertByDN(CertDN);
	if (pCertContext == NULL)
	{
		MsgBox(_T("SelectCertByDN"));
		goto error;
	}
	else
	{
	}

	
	bRet = CryptAcquireContext(
			&hCryptProv,
			NULL,
			NULL,
			PROV_RSA_FULL,
			CRYPT_VERIFYCONTEXT
		);
	if (!bRet)
	{
		MsgBox(_T("CryptAcquireContext"));
		goto error;
	}

	
	bRet = CryptCreateHash(
			hCryptProv, 
			CALG_MD5, 
			0, 
			0, 
			&hHash
		);
	if (!bRet)
	{
		MsgBox(_T("CryptCreateHash"));
		goto error;
	}

	// 对原文生成摘要
	//BYTE rgbFile[1024];
	//memset(rgbFile, 0, sizeof(rgbFile));
	//std::string str = "hellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohello";
	//int len = str.length();
	//memcpy(rgbFile, str.c_str(), len);

	int RawDataLen = 0;
	RawDataLen = _tcslen(RawData);
	bRet = CryptHashData(
				hHash, 
				(BYTE*) RawData, 
				RawDataLen, 
				0
			);
	if (!bRet)
	{
		MsgBox(_T("CryptHashData"));
		goto error;

	}

	
	bRet = CryptImportPublicKeyInfo(
			hCryptProv, 
			PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
			&pCertContext->pCertInfo->SubjectPublicKeyInfo,
			&hPubKey
		);
	if (!bRet)
	{
		MsgBox(_T("CryptImportPublicKeyInfo"));
		goto error;
	}

	
	bRet = CryptVerifySignature(
			hHash, 
			(const BYTE*)pbSignature, 
			cbSignLen, 
			hPubKey,
			NULL, 
			0
		);
	if (bRet)
	{
		MsgBox(_T("验签成功"));
	}
	else
	{
		MsgBox(_T("CryptVerifySignature"));
	}

error:
//	free(pbSignature);

	if (hHash)
		CryptDestroyHash(hHash);

	if (pCertContext)
		CertFreeCertificateContext(pCertContext);

	if (hCertStore)
		CertCloseStore(		hCertStore, 		0	);

	if (hCryptProv)
		CryptReleaseContext(		hCryptProv,		0	);

	return bRet;
}

// ok
PCCERT_CONTEXT CCertActiveXCtrl::SelectCertByDN(LPCTSTR pDN)
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
     _T("MY"));  

	if (hCertStore == NULL)
		return NULL;

	MsgBox(pDN);

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

		

		CString dn;
		ConvertCertDN(pszString, dn);
		MsgBox(dn);
		
		//MessageBox(pDN);
		//MessageBox(dn);

		if (_tcscmp(pDN, dn) == 0)
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

// ok
void CCertActiveXCtrl::MsgBox(LPCTSTR lpMsg)
{


#ifdef _DEBUG
	AfxMessageBox(lpMsg);
#endif
}
/*
void CCertActiveXCtrl::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	char * str = "测试123";
	TRACE("mbcs str len %d\n", strlen(str));

	wchar_t* result = NULL;
	result = myA2W(str);
	TRACE("wide str len %d\n", _tcslen(result));
	

	if (result != NULL)
	{
		delete[] result;
		result = NULL;
	}
}
*/

wchar_t *  CCertActiveXCtrl::A2W_(const char * lpStr)
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
/*
void CCertActiveXCtrl::OnBnClickedButton2()
{
	// TODO: 在此添加控件通知处理程序代码
	wchar_t * str = L"测试123";
	TRACE("wide str len %d\n", _tcslen(str));

	char* result = NULL;
	result = myW2A(str);
	TRACE("mbcs str len %d\n", strlen(result));
	

	if (result != NULL)
	{
		delete[] result;
		result = NULL;
	}
}
*/

char *  CCertActiveXCtrl::W2A_(const wchar_t * lpwStr)
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


SHORT CCertActiveXCtrl::DeleteCert(LPCTSTR DN)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());

	// TODO: 在此添加调度处理程序代码
	if (DN == NULL)
		return 0;

	PCCERT_CONTEXT   pCertContext = NULL; 
	pCertContext = SelectCertByDN(DN);
	if (pCertContext == NULL)
		return 0;

	BOOL bRet = CertDeleteCertificateFromStore(pCertContext);
	return bRet;
}

BOOL CCertActiveXCtrl::ConvertCertDN(LPCTSTR CertDN, CString& Result)
{
	
	int i=0;
	CString strItem;
	std::vector<CString> vItems;


	while (AfxExtractSubString(strItem, CertDN, i, ','))
	{
		i++;
		strItem = strItem.TrimLeft();

		vItems.push_back(strItem);
	}


	int count = vItems.size();
	if (count <= 1)
	{
		return FALSE;
	}

	for (int j=count-1 ; j >=0; j--)
	{
		Result += vItems[j];
		if (j != 0 )
		{
			Result += ',';
			//Result += ' '; // 空格
		}
	}

	
	return TRUE;
}


BSTR CCertActiveXCtrl::ConvertDN(LPCTSTR DN)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());

	CString strResult;

	// TODO: 在此添加调度处理程序代码
	ConvertCertDN(DN, strResult);
	//MessageBox(strResult);

	return strResult.AllocSysString();
}
