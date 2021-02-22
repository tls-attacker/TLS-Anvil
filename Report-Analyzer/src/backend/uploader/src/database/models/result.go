package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type Result struct {
	ID                                      primitive.ObjectID   `bson:"_id"`
	ContainerId                             primitive.ObjectID   `bson:"ContainerId"`
	TestMethod                              TestMethod           `bson:"TestMethod"`
	Result                                  string               `bson:"Result"`
	HasStateWithAdditionalResultInformation bool                 `bson:"HasStateWithAdditionalResultInformation"`
	HasVaryingAdditionalResultInformation   bool                 `bson:"HasVaryingAdditionalResultInformation"`
	DisabledReason                          *string              `bson:"DisabledReason"`
	FailedReason                            *string              `bson:"FailedReason"`
	FailedStacktrace                        *string              `bson:"FailedStacktrace"`
	ElapsedTime                             int                  `bson:"ElapsedTime"`
	States                                  []primitive.ObjectID `bson:"States" json:"-"`
	StatesStructs                           []State              `bson:"-" json:"States"`
	StatesCount                             int                  `bson:"StatesCount"`
	StateIndexMap                           map[string]int       `bson:"StateIndexMap"`
	Score                                   map[string]Score     `bson:"Score"`
	FailureInducingCombinations             []map[string]string  `bson:"FailureInducingCombinations"`
	CreatedAt                               time.Time            `bson:"createdAt"`
	UpdatedAt                               time.Time            `bson:"updatedAt"`
}
