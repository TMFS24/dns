/*
Date: 2019-02-05 
Author: tmfs24@gmail.com

Simple DNS Resolver; makes a DNS request to the DNS Server provided over UDP and returns the result.

Responses currently limited to 512 bytes.

*/

package main

import (

	"fmt"
	"strings"
	"net"
	"encoding/hex"
	"encoding/binary"
	"crypto/rand"

)


type QTYPE uint16
//type QTYPE uint16

type message struct {// DNS MESSAGE FORMAT

	//Header []byte
	Header header
	//Question []byte
	Question question
	Answer []byte
	Authority []byte
	Additional []byte

}

type header struct {

	id []byte
	flags []byte
	qdcount []byte
	ancount []byte
	nscount []byte
	arcount []byte

}

func (h header) getBytes () ([]byte) {

	var retBytes []byte
	retBytes = append(retBytes, h.id...)
	retBytes = append(retBytes, h.flags...)
	retBytes = append(retBytes, h.qdcount...)
	retBytes = append(retBytes, h.ancount...)
	retBytes = append(retBytes, h.nscount...)
	retBytes = append(retBytes, h.arcount...)
//	fmt.Println("H:" , retBytes)
	return retBytes

}


type question struct {
	labels []byte
	querytype QTYPE
	queryclass []byte
}

func (q question) getBytes() ([]byte) {
	
	var retBytes []byte
	var querytypebytes = make([]byte, 2)
	retBytes = append(retBytes, q.labels...)
	binary.BigEndian.PutUint16(querytypebytes, uint16(q.querytype))
	retBytes = append(retBytes, querytypebytes...)
	retBytes = append(retBytes, q.queryclass...)

	//fmt.Println("Q: ", retBytes)
	return retBytes
	
}

type resrecord struct {
	labels []byte
	querytype QTYPE
	queryclass []byte
	ttl []byte
	datalength []byte
	resdata []byte
}


const (

	A QTYPE = iota + 1
	NS
	MD
	MF
	CNAME
	SOA
	MB
	MG
	MR
	NULL
	WKS
	PTR
	HINFO
	MINFO
	MX
	TXT

	//Not supporting AXFR, MAILB, MAILA or *
)

func Query(queryString string) message { //returns DNS message set as a Query
	newQuery := message{}
	newQuery.Header = createQueryHeader()
	newQuery.Question = createQueryQuestion(queryString)
	//fmt.Println(newquery.Header.getBytes(),newquery.Question.getBytes())
	return newQuery

}

func generateID() ([]byte) { //create 2 random bytes for Message ID

	randBytes := make([]byte, 2)
	rand.Read(randBytes)

	return randBytes
}



func createQueryHeader() (header){

	/*
		Query Header Created for STANDARD DNS Request only - 1 Question, not truncated
	*/
	
	var retHeader header 

	//ID Field (16 bits)

	//id :=make([]byte,2)
	//id = generateID()
	retHeader.id = generateID()


	//Flag Field (16 bits)
	//flags :=make([]byte ,2)
	//flags[0] = 0x01 //Recursion is desired.
	retHeader.flags =[]byte{0x01,0x00} 

	//qdcount Field (16 bits) 
	//qdcount :=make([]byte, 2)
	//qdcount[1] = 0x01 //1 Question
	retHeader.qdcount = []byte{0x00,0x01}

	//var ancount uint16 = 0
	//ancount := make([]byte, 2)
	retHeader.ancount =[]byte{0x00,0x00}

	//var nscount uint16 = 0
	//nscount :=make([]byte, 2)
	retHeader.nscount =[]byte{0x00,0x00}

	//var arcount uint16 = 0
	//arcount :=make([]byte, 2)
	retHeader.arcount =[]byte{0x00,0x00}

        //build the header 
        /*header :=make([]byte,12)
	header[0] = id[0]
	header[1] = id[1]
	header[6] = ancount[0]
	header[7] = ancount[1]
	header[8] = nscount[0]
	header[9] = nscount [1]
	header[10] = arcount[0]
	header[11] = arcount[1]
*/
	return retHeader
}

func createQueryQuestion(queryString string) (question) {


	var retQuestion question
	
	//split into labels, then place into correct format (<LEN><LABEL><LEN><LABEL>...<00>)
	labels := strings.Split(queryString, ".")


	var labelBytes []byte

	for _, v := range labels {

		//fmt.Println(len(v))
		labelBytes = append(labelBytes, byte(len(v)))
		labelBytes = append(labelBytes, []byte(v)...)


	}
	labelBytes = append(labelBytes, byte(0))
	retQuestion.labels = labelBytes
	//define labels
	//QType for record type)
	//questionQTYPE := make([]byte, 2)
	//questionQCLASS := make([]byte, 2)

	//binary.BigEndian.PutUint16(retQuestion.querytype, uint16(A))
	retQuestion.querytype = A
	retQuestion.queryclass = []byte{0x00,0x01}	//QCLASS of 1 (IN)

	//questionBytes = append(questionBytes, questionQTYPE...)
//	questionBytes = append(questionBytes, questionQCLASS...)


	return retQuestion

}

func (q message) getQuery(ip string) ([]byte) {//need to confirm this is query not response.
	ans := make([]byte, 512)
	//var ans []byte
	var host string = ip
	var port string = "53" //Default Port Only

	var target string = host + ":" +port

	conn, err := net.Dial("udp", target)
	if err != nil {
		fmt.Println("ERROR Creating Connection")
	}

	defer conn.Close()

	conn.Write(append(q.Header.getBytes(), q.Question.getBytes()...))
	if err != nil {
		fmt.Println("ERROR Writing Message")
	}
	_,err = conn.Read(ans)

	if err != nil {
		fmt.Println("ERROR Reading Bytes")
	}
	return ans

}

func getAnswer (rawInput[]byte) (message) {

	var retMessage message
	retMessage.Header = makeHeader(rawInput[0:12])
	//retMessage.Question = makeQuestion



	return retMessage


}

func makeHeader(rawInput []byte) (header) {

	var retHeader header
	retHeader.id = rawInput[0:2]
	retHeader.flags = rawInput[2:4]
	retHeader.qdcount = rawInput[4:6]
	retHeader.ancount = rawInput[6:8]
	retHeader.nscount = rawInput[8:10]
	retHeader.arcount = rawInput[10:12]

	return retHeader

}



func main() {

	dnsquery := Query("google.com")
	fmt.Println(getAnswer(dnsquery.getQuery("8.8.8.8")).Header.getBytes())

	//Question Section
/*
	var qtype QTYPE = TXT //A Record
	fmt.Println(qtype)
	//var qclass uint16 = 1 //IN (Internet Class)


*/
	// "06676f6f676c6503636f6d00" //google.com as a qname

	var query string = "24240100000100000000000006676f6f676c6503636f6d00000f0001"
	decoded,_ := hex.DecodeString(query)



	fmt.Println(append(dnsquery.Header.getBytes(), dnsquery.Question.getBytes()...) )
	fmt.Println(decoded)
	



	//UDP Connection
/*
	var host string = "8.8.8.8"
	var port string = "53"

	var target string = host + ":" +port

	conn, err := net.Dial("udp", target)
	if err != nil {
		fmt.Println("ERROR")
	}

	defer conn.Close()

	//conn.Write(decoded)
	conn.Write(append(dnsquery.Header, dnsquery.Question...))
	buffer := make([]byte,1024)
	conn.Read(buffer)
	fmt.Println(buffer)*/

}
