package pagetoken

import "encoding/json"

type (
	Token = string

	Payload struct {
		LastID   string `json:"lastID"`
		PageSize int    `json:"pageSize"`
	}
)

func (p *Payload) ToMap() map[string]interface{} {
	var data map[string]interface{}
	b, err := json.Marshal(p)
	if err != nil {
		return nil
	}
	if err := json.Unmarshal(b, &data); err != nil {
		return nil
	}

	return data
}
