#ifndef _CERT_DLL_H_
#define _CERT_DLL_H_

#include <Windows.h>
#include <tchar.h>
#include <wincrypt.h>
#include <cryptuiapi.h>
#include <Xenroll.h>
#include <sstream>
#include <fstream>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "cryptui.lib")



// 添加信任站点
int __stdcall AddTrustedWebSite(LPCTSTR lpWebSite);
// 安装根证书
int __stdcall InstallRootCert(LPCTSTR lpCertFile);
// 安装二级证书
int __stdcall InstallCACert(LPCTSTR lpCertFile);


// 根据证书DN查找证书
int __stdcall FindCertByDN(LPCTSTR Store, LPCTSTR DN);
// 删除指定证书
int __stdcall DeleteCert(LPCTSTR DN);

// 申请证书
int __stdcall CreateCSRWinXP(LPTSTR result);
int __stdcall CreateCSRWin7(LPTSTR result);
// 安装个人证书
int __stdcall InstallCertWinXP(LPCTSTR Cert);
int __stdcall InstallCertWin7(LPCTSTR Cert);

// 签名
int __stdcall Sign(LPCTSTR CertDN, LPCTSTR RawData, LPSTR SignResult);
// 验签
int __stdcall Verify();

// 写日志文件
int __stdcall WriteInstallLog(LPCTSTR lpFileName, LPCTSTR lpLog);

#endif