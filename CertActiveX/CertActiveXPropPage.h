#pragma once

// CertActiveXPropPage.h : CCertActiveXPropPage 属性页类的声明。


// CCertActiveXPropPage : 有关实现的信息，请参阅 CertActiveXPropPage.cpp。

class CCertActiveXPropPage : public COlePropertyPage
{
	DECLARE_DYNCREATE(CCertActiveXPropPage)
	DECLARE_OLECREATE_EX(CCertActiveXPropPage)

// 构造函数
public:
	CCertActiveXPropPage();

// 对话框数据
	enum { IDD = IDD_PROPPAGE_CERTACTIVEX };

// 实现
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 消息映射
protected:
	DECLARE_MESSAGE_MAP()
};

