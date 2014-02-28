#pragma once

// CertActiveXCtrl.h : CCertActiveXCtrl ActiveX 控件类的声明。


// CCertActiveXCtrl : 有关实现的信息，请参阅 CertActiveXCtrl.cpp。

class CCertActiveXCtrl : public COleControl
{
	DECLARE_DYNCREATE(CCertActiveXCtrl)

// 构造函数
public:
	CCertActiveXCtrl();

// 重写
public:
	virtual void OnDraw(CDC* pdc, const CRect& rcBounds, const CRect& rcInvalid);
	virtual void DoPropExchange(CPropExchange* pPX);
	virtual void OnResetState();

// 实现
protected:
	~CCertActiveXCtrl();

	DECLARE_OLECREATE_EX(CCertActiveXCtrl)    // 类工厂和 guid
	DECLARE_OLETYPELIB(CCertActiveXCtrl)      // GetTypeInfo
	DECLARE_PROPPAGEIDS(CCertActiveXCtrl)     // 属性页 ID
	DECLARE_OLECTLTYPE(CCertActiveXCtrl)		// 类型名称和杂项状态

// 消息映射
	DECLARE_MESSAGE_MAP()

// 调度映射
	DECLARE_DISPATCH_MAP()

// 事件映射
	DECLARE_EVENT_MAP()

// 调度和事件 ID
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

