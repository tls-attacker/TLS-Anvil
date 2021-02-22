package models

type Score struct {
	Total         float32 `bson:"Total"`
	Reached       float32 `bson:"Reached"`
	Percentage    float32 `bson:"Percentage"`
	SeverityLevel string  `bson:"SeverityLevel"`
}
