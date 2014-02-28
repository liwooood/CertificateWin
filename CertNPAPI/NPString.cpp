//kk: helper to wrap some common string tasks

#include "NPString.h"

CNPString::CNPString(NPString npString) : m_pszData(0), m_len(0)
{
	Set( npString.UTF8Characters, npString.UTF8Length );
}

CNPString::CNPString(LPCTSTR psz, int len) : m_pszData(0), m_len(0)
{
	Set( psz, len );
}

CNPString::~CNPString()
{
	delete m_pszData;
}

void CNPString::Set(LPCTSTR psz, int len)
{
	delete m_pszData;

	m_len = len + 1;
	m_pszData = new TCHAR[m_len];

	strncpy( m_pszData, psz, m_len );
	m_pszData[len] = '\0';
}

CNPString::operator LPCTSTR()
{
	return m_pszData;
}

int CNPString::Compare(LPCTSTR psz)
{
	if( m_pszData )
	{
		return strcmp( m_pszData, psz );
	}

	return -1;
}