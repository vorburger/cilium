// Code generated by go-swagger; DO NOT EDIT.

package daemon

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	models "github.com/cilium/cilium/api/v1/models"
)

// GetDebuginfoOKCode is the HTTP code returned for type GetDebuginfoOK
const GetDebuginfoOKCode int = 200

/*GetDebuginfoOK Success

swagger:response getDebuginfoOK
*/
type GetDebuginfoOK struct {

	/*
	  In: Body
	*/
	Payload *models.DebugInfo `json:"body,omitempty"`
}

// NewGetDebuginfoOK creates GetDebuginfoOK with default headers values
func NewGetDebuginfoOK() *GetDebuginfoOK {

	return &GetDebuginfoOK{}
}

// WithPayload adds the payload to the get debuginfo o k response
func (o *GetDebuginfoOK) WithPayload(payload *models.DebugInfo) *GetDebuginfoOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get debuginfo o k response
func (o *GetDebuginfoOK) SetPayload(payload *models.DebugInfo) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetDebuginfoOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// GetDebuginfoFailureCode is the HTTP code returned for type GetDebuginfoFailure
const GetDebuginfoFailureCode int = 500

/*GetDebuginfoFailure DebugInfo get failed

swagger:response getDebuginfoFailure
*/
type GetDebuginfoFailure struct {

	/*
	  In: Body
	*/
	Payload models.Error `json:"body,omitempty"`
}

// NewGetDebuginfoFailure creates GetDebuginfoFailure with default headers values
func NewGetDebuginfoFailure() *GetDebuginfoFailure {

	return &GetDebuginfoFailure{}
}

// WithPayload adds the payload to the get debuginfo failure response
func (o *GetDebuginfoFailure) WithPayload(payload models.Error) *GetDebuginfoFailure {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get debuginfo failure response
func (o *GetDebuginfoFailure) SetPayload(payload models.Error) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetDebuginfoFailure) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(500)
	payload := o.Payload
	if err := producer.Produce(rw, payload); err != nil {
		panic(err) // let the recovery middleware deal with this
	}

}
