interface ErrtionOptions {
	/** The message to use for the error */
	message: string
	/** The code to categorise the error */
	code: string | number
	/** The severity level of the error */
	level?: string | number
	/** The parent of the error */
	parent?: Errtion | Error
}

export interface Errtion extends Error, ErrtionOptions {}

/**
 * Allow code and level inputs on Errlop.
 * We do this instead of a class extension, as class extensions do not interop well on node 0.8, which is our target.
 */
export function errtion(
	this: void,
	opts: ErrtionOptions,
	parent?: Errtion | Error
): Errtion {
	// extract opts
	const { code, level } = opts
	let { message } = opts
	if (parent == null) parent = opts.parent

	// append message
	if (code) message = `${code}: ${message}`
	if (level) message = `${level}: ${message}`
	if (parent) message = `${message}\n↪${parent.message || parent}`

	// create error
	const error = new Error(message) as Errtion

	// add properties
	if (code) error.code = code
	if (level) error.level = level
	if (parent) error.parent = parent

	// return
	return error
}
