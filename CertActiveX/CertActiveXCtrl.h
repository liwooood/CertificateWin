#pragma once

// CertActiveXCtrl.h : CCertActiveXCtrl ActiveX �ؼ����������


// CCertActiveXCtrl : �й�ʵ�ֵ���Ϣ������� CertActiveXCtrl.cpp��

class CCertActiveXCtrl : public COleControl
{
	DECLARE_DYNCREATE(CCertActiveXCtrl)

// ���캯��
public:
	CCertActiveXCtrl();

// ��д
public:
	virtual void OnDraw(CDC* pdc, const CRect& rcBounds, const CRect& rcInvalid);
	virtual void DoPropExchange(CPropExchange* pPX);
	virtual void OnResetState();

// ʵ��
protected:
	~CCertActiveXCtrl();

	DECLARE_OLECREATE_EX(CCertActiveXCtrl)    // �๤���� guid
	DECLARE_OLETYPELIB(CCertActiveXCtrl)      // GetTypeInfo
	DECLARE_PROPPAGEIDS(CCertActiveXCtrl)     // ����ҳ ID
	DECLARE_OLECTLTYPE(CCertActiveXCtrl)		// �������ƺ�����״̬

// ��Ϣӳ��
	DECLARE_MESSAGE_MAP()

// ����ӳ��
	DECLARE_DISPATCH_MAP()

// �¼�ӳ��
	DECLARE_EVENT_MAP()

// ���Ⱥ��¼� ID
public:
	enum {
		dispidConvertDN = 7L,
		dispidDeleteCert = 6L,
		dispidVerify = 5L,
		dispidSign = 4L,

		dispidInstallCert = 3L,
		dispidCreateCSR = 2L,
		dispidFindCertByDN = 1L
	};
	
protected:
	
	SHORT FindCertByDN(LPCTSTR DN);
	BSTR CreateCSR(void);
	SHORT InstallCert(LPCTSTR Cert);
	
	BSTR Sign(LPCTSTR CertDN, LPCTSTR RawData);
	SHORT Verify(LPCTSTR CertDN, LPCTSTR RawData, LPCTSTR SignResult);
	SHORT DeleteCert(LPCTSTR DN);
	BSTR ConvertDN(LPCTSTR DN);

private:
	PCCERT_CONTEXT SelectCertByDN(LPCTSTR pCertDN);
	void MsgBox(LPCTSTR lpMsg);

	wchar_t * A2W_(const char * lpStr);
	char * W2A_(const wchar_t * lpwStr);
	BOOL ConvertCertDN(LPCTSTR CertDN, CString& Result);

	
protected:
	
};

