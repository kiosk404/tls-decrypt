/**
* @Author: kiosk
* @Mail: weijiaxiang007@foxmail.com
* @Date: 2020/12/27
**/
package packet

import "sync"

/*
 * The UDP factory: returns a new Stream
 */
type UdpStreamFactory struct {
	WG     	sync.WaitGroup
}