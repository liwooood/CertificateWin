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



// �������վ��
int __stdcall AddTrustedWebSite(LPCTSTR lpWebSite);
// ��װ��֤��
int __stdcall InstallRootCert(LPCTSTR lpCertFile);
// ��װ����֤��
int __stdcall InstallCACert(LPCTSTR lpCertFile);


// ����֤��DN����֤��
int __stdcall FindCertByDN(LPCTSTR Store, LPCTSTR DN);
// ɾ��ָ��֤��
int __stdcall DeleteCert(LPCTSTR DN);

// ����֤��
int __stdcall CreateCSRWinXP(LPTSTR result);
int __stdcall CreateCSRWin7(LPTSTR result);
// ��װ����֤��
int __stdcall InstallCertWinXP(LPCTSTR Cert);
int __stdcall InstallCertWin7(LPCTSTR Cert);

// ǩ��
int __stdcall Sign(LPCTSTR CertDN, LPCTSTR RawData, LPSTR SignResult);
// ��ǩ
int __stdcall Verify();

// д��־�ļ�
int __stdcall WriteInstallLog(LPCTSTR lpFileName, LPCTSTR lpLog);

#endif