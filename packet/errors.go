/**
 * Reversing Space: Dominons 4 Network Analysis
 * Copyright (c) 2015-2016 A.W. Stanley.
 *
 * This software is provided 'as-is', without any express or implied warranty.
 * In no event will the authors be held liable for any damages arising from
 * the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 *   1. The origin of this software must not be misrepresented; you must
 *      not claim that you wrote the original software. If you use this
 *      software in a product, an acknowledgment in the product
 *      documentation would be appreciated but is not required.
 *
 *   2. Altered source versions must be plainly marked as such, and
 *      must not be misrepresented as being the original software.
 *
 *   3. This notice may not be removed or altered from any
 *      source distribution.
 *
**/

package packet

import (
	"fmt"
)

// A ReadError represents an error which occurs during reading.
// It wraps the internal error and displays additional information.
type ReadError struct {
	// Display error
	Display string

	// Internal error value
	Err error
}

// Error implements the error interface; it returns the string value of an
// error message.  In this case it performs the wrapping.
func (r ReadError) Error() string {
	return fmt.Sprintf("readerror: %s (inner: %s)", r.Display, r.Err)
}

// newReadError creates a new ReadError wrapper.
func newReadError(str string, err error) error {
	return ReadError{
		Display: str,
		Err:     err,
	}
}

// A WriteError represents an error which occurs during writing.
// It wraps the internal error and displays additional information.
type WriteError struct {
	// Display error
	Display string

	// Internal error value
	Err error
}

// Error implements the error interface; it returns the string value of an
// error message.  In this case it performs the wrapping.
func (r WriteError) Error() string {
	return fmt.Sprintf("readerror: %s (inner: %s)", r.Display, r.Err)
}

// newWriteError creates a new WriteError wrapper.
func newWriteError(str string, err error) error {
	return ReadError{
		Display: str,
		Err:     err,
	}
}
