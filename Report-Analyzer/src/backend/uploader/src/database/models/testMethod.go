package models

type TestMethod struct {
	Description     string `bson:"Description"`
	TestDescription string `bson:"TestDescription"`
	TlsVersion      string `bson:"TlsVersion"`
	RFC             struct {
		Section string `bson:"Section"`
		Number  int    `bson:"Number"`
	} `bson:"RFC"`
	MethodName  string `bson:"MethodName"`
	DisplayName string `bson:"DisplayName"`
	ClassName   string `bson:"ClassName"`
}
