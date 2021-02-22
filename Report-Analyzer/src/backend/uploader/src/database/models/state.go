package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type State struct {
	ID                          primitive.ObjectID `bson:"_id"`
	TestResultId                primitive.ObjectID `bson:"TestResultId"`
	ContainerId                 primitive.ObjectID `bson:"ContainerId"`
	DerivationContainer         map[string]string  `bson:"DerivationContainer"`
	DisplayName                 string             `bson:"DisplayName"`
	Result                      string             `bson:"Result"`
	AdditionalResultInformation string             `bson:"AdditionalResultInformation"`
	AdditionalTestInformation   string             `bson:"AdditionalTestInformation"`
	SrcPort                     int                `bson:"SrcPort"`
	DstPort                     int                `bson:"DstPort"`
	StartTimestamp              string             `bson:"StartTimestamp"`
	EndTimestamp                string             `bson:"EndTimestamp"`
	Uuid                        string             `bson:"uuid"`
	Stacktrace                  string             `bson:"Stacktrace"`
	CreatedAt                   time.Time          `bson:"createdAt"`
	UpdatedAt                   time.Time          `bson:"updatedAt"`
}
