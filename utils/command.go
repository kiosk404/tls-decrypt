/**
* @Author: kiosk
* @Mail: weijiaxiang007@foxmail.com
* @Date: 2020/12/27
**/
package utils

type Command struct {
	Maxcount 		int
	Snaplen 		int
	Decoder 		string
	Output			string
	Iface 			string
	Fname 			string
	Promisc 		bool
	Lazy			bool
	Nodefrag    	bool
	Checksum 		bool
	Nooptcheck  	bool
	Ignorefsmerr	bool
	Verbose			bool
	Quiet			bool
	Nohttp 			bool
	Hexdump			bool
	Hexdumppkt		bool
}