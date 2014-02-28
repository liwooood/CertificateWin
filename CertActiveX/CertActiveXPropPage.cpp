// CertActiveXPropPage.cpp : CCertActiveXPropPage 属性页类的实现。

#include "stdafx.h"
#include "CertActiveX.h"
#include "CertActiveXPropPage.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


IMPLEMENT_DYNCREATE(CCertActiveXPropPage, COlePropertyPage)



// 消息映射

BEGIN_MESSAGE_MAP(CCertActiveXPropPage, COlePropertyPage)
END_MESSAGE_MAP()



// 初始化类工厂和 guid

IMPLEMENT_OLECREATE_EX(CCertActiveXPropPage, "CERTACTIVEX.CertActiveXPropPage.1",
	0x6868ef0e, 0xe28, 0x428e, 0xb0, 0x98, 0xc6, 0x9e, 0xcb, 0x97, 0xc4, 0x43)



// CCertActiveXPropPage::CCertActiveXPropPageFactory::UpdateRegistry -
// 添加或移除 CCertActiveXPropPage 的系统注册表项

BOOL CCertActiveXPropPage::CCertActiveXPropPageFactory::UpdateRegistry(BOOL bRegister)
{
	if (bRegister)
		return AfxOleRegisterPropertyPageClass(AfxGetInstanceHandle(),
			m_clsid, IDS_CERTACTIVEX_PPG);
	else
		return AfxOleUnregisterClass(m_clsid, NULL);
}



// CCertActiveXPropPage::CCertActiveXPropPage - 构造函数

CCertActiveXPropPage::CCertActiveXPropPage() :
	COlePropertyPage(IDD, IDS_CERTACTIVEX_PPG_CAPTION)
{
}



// CCertActiveXPropPage::DoDataExchange - 在页和属性间移动数据

void CCertActiveXPropPage::DoDataExchange(CDataExchange* pDX)
{
	DDP_PostProcessing(pDX);
}



// CCertActiveXPropPage 消息处理程序
