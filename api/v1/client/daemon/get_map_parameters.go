// Code generated by go-swagger; DO NOT EDIT.

package daemon

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"

	strfmt "github.com/go-openapi/strfmt"
)

// NewGetMapParams creates a new GetMapParams object
// with the default values initialized.
func NewGetMapParams() *GetMapParams {

	return &GetMapParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewGetMapParamsWithTimeout creates a new GetMapParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetMapParamsWithTimeout(timeout time.Duration) *GetMapParams {

	return &GetMapParams{

		timeout: timeout,
	}
}

// NewGetMapParamsWithContext creates a new GetMapParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetMapParamsWithContext(ctx context.Context) *GetMapParams {

	return &GetMapParams{

		Context: ctx,
	}
}

// NewGetMapParamsWithHTTPClient creates a new GetMapParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetMapParamsWithHTTPClient(client *http.Client) *GetMapParams {

	return &GetMapParams{
		HTTPClient: client,
	}
}

/*GetMapParams contains all the parameters to send to the API endpoint
for the get map operation typically these are written to a http.Request
*/
type GetMapParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get map params
func (o *GetMapParams) WithTimeout(timeout time.Duration) *GetMapParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get map params
func (o *GetMapParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get map params
func (o *GetMapParams) WithContext(ctx context.Context) *GetMapParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get map params
func (o *GetMapParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get map params
func (o *GetMapParams) WithHTTPClient(client *http.Client) *GetMapParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get map params
func (o *GetMapParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *GetMapParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
