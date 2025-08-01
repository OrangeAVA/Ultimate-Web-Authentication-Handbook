/*

Appendix-A: The Go Programming Language Reference
Ultimate Web Authentication Handbook by Sambit Kumar Dash

This sample code is from the examples of "https://github.com/gonutz/sudoku."
If you want to use a package in your code, you create your module and import
the package there. You can use this sample file by creating your module and
adding this file as part of the module.

*/

package main

import (
	"fmt"

	"github.com/gonutz/sudoku"
)

func main() {
	fmt.Println(sudoku.Solve(sudoku.Game{
		0, 0, 0, 0, 8, 4, 0, 0, 5,
		0, 9, 0, 0, 0, 0, 0, 0, 3,
		0, 0, 7, 0, 1, 3, 0, 0, 0,
		0, 0, 5, 0, 0, 0, 1, 3, 0,
		7, 0, 0, 0, 3, 0, 0, 0, 9,
		0, 8, 3, 0, 0, 0, 2, 0, 0,
		0, 0, 0, 6, 9, 0, 5, 0, 0,
		2, 0, 0, 0, 0, 0, 0, 9, 0,
		1, 0, 0, 5, 7, 0, 0, 0, 0,
	}))
}
