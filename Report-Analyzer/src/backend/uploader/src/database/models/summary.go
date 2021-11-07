package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type Summary struct {
	ID                            primitive.ObjectID   `bson:"_id"`
	PcapStorageId                 primitive.ObjectID   `bson:"PcapStorageId"`
	KeylogfileStorageId           primitive.ObjectID   `bson:"KeylogfileStorageId"`
	Identifier                    string               `bson:"Identifier"`
	ShortIdentifier               string               `bson:"ShortIdentifier"`
	DateInt                       int                  `bson:"-" json:"Date"`
	Date                          time.Time            `bson:"Date" json:"-"`
	DisplayName                   string               `bson:"DisplayName"`
	ElapsedTime                   int                  `bson:"ElapsedTime"`
	FailedTests                   int                  `bson:"FailedTests"`
	SucceededTests                int                  `bson:"SucceededTests"`
	DisabledTests                 int                  `bson:"DisabledTests"`
	TestResultClassMethodIndexMap map[string]int       `bson:"TestResultClassMethodIndexMap"`
	StatesCount                   int                  `bson:"StatesCount"`
	Score                         map[string]Score     `bson:"Score"`
	TestResults                   []primitive.ObjectID `bson:"TestResults"  json:"-"`
	CreatedAt                     time.Time            `bson:"createdAt"  json:"-"`
	UpdatedAt                     time.Time            `bson:"updatedAt" json:"-"`
}
