// CertActiveXPropPage.cpp : CCertActiveXPropPage ����ҳ���ʵ�֡�

#include "stdafx.h"
#include "CertActiveX.h"
#include "CertActiveXPropPage.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


IMPLEMENT_DYNCREATE(CCertActiveXPropPage, COlePropertyPage)



// ��Ϣӳ��

BEGIN_MESSAGE_MAP(CCertActiveXPropPage, COlePropertyPage)
END_MESSAGE_MAP()



// ��ʼ���๤���� guid

IMPLEMENT_OLECREATE_EX(CCertActiveXPropPage, "CERTACTIVEX.CertActiveXPropPage.1",
	0x6868ef0e, 0xe28, 0x428e, 0xb0, 0x98, 0xc6, 0x9e, 0xcb, 0x97, 0xc4, 0x43)



// CCertActiveXPropPage::CCertActiveXPropPageFactory::UpdateRegistry -
// ��ӻ��Ƴ� CCertActiveXPropPage ��ϵͳע�����

BOOL CCertActiveXPropPage::CCertActiveXPropPageFactory::UpdateRegistry(BOOL bRegister)
{
	if (bRegister)
		return AfxOleRegisterPropertyPageClass(AfxGetInstanceHandle(),
			m_clsid, IDS_CERTACTIVEX_PPG);
	else
		return AfxOleUnregisterClass(m_clsid, NULL);
}



// CCertActiveXPropPage::CCertActiveXPropPage - ���캯��

CCertActiveXPropPage::CCertActiveXPropPage() :
	COlePropertyPage(IDD, IDS_CERTACTIVEX_PPG_CAPTION)
{
}



// CCertActiveXPropPage::DoDataExchange - ��ҳ�����Լ��ƶ�����

void CCertActiveXPropPage::DoDataExchange(CDataExchange* pDX)
{
	DDP_PostProcessing(pDX);
}



// CCertActiveXPropPage ��Ϣ�������
