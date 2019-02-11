// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/swag"
)

// ConnectivityStatus Connectivity status of a path
// swagger:model ConnectivityStatus
type ConnectivityStatus struct {

	// Round trip time to node in nanoseconds
	Latency int64 `json:"latency,omitempty"`

	// Human readable status/error/warning message
	Status string `json:"status,omitempty"`
}

// Validate validates this connectivity status
func (m *ConnectivityStatus) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ConnectivityStatus) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ConnectivityStatus) UnmarshalBinary(b []byte) error {
	var res ConnectivityStatus
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
