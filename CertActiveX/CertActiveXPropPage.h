#pragma once

// CertActiveXPropPage.h : CCertActiveXPropPage ����ҳ���������


// CCertActiveXPropPage : �й�ʵ�ֵ���Ϣ������� CertActiveXPropPage.cpp��

class CCertActiveXPropPage : public COlePropertyPage
{
	DECLARE_DYNCREATE(CCertActiveXPropPage)
	DECLARE_OLECREATE_EX(CCertActiveXPropPage)

// ���캯��
public:
	CCertActiveXPropPage();

// �Ի�������
	enum { IDD = IDD_PROPPAGE_CERTACTIVEX };

// ʵ��
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ��Ϣӳ��
protected:
	DECLARE_MESSAGE_MAP()
};

