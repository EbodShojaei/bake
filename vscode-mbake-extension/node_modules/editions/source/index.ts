// Imports
import { resolve } from 'path'
import matchRange from 'version-range'
import { errtion, Errtion } from './util.js'
import { versions as processVersions } from 'process'
import { readFileSync } from 'fs'

export type Range = string | boolean
export type Engines = false | { [engine: string]: Range }
export type Versions = { [engine: string]: string }

/**
 * Edition entries must conform to the following specification.
 * @example
 * ``` json
 * {
 *   "description": "esnext source code with require for modules",
 *   "directory": "source",
 *   "entry": "index.js",
 *   "tags": [
 *     "javascript",
 *     "esnext",
 *     "require"
 *   ],
 *   "engines": {
 *     "node": ">=6",
 *     "browsers": "defaults"
 *   }
 * }
 * ```
 */
export interface Edition {
	/**
	 * Use this property to describe the edition in human readable terms. Such as what it does and who it is for. It is used to reference the edition in user facing reporting, such as error messages.
	 * @example
	 * ``` json
	 * "esnext source code with require for modules"
	 * ```
	 */
	description: string

	/**
	 * The location to where this directory is located. It should be a relative path from the `package.json` file.
	 * @example
	 * ``` json
	 * "source"
	 * ```
	 */
	directory: string

	/**
	 * The default entry location for this edition, relative to the edition's directory.
	 * @example
	 * ``` json
	 * "index.js"
	 * ```
	 */
	entry: string

	/**
	 * Any keywords you wish to associate to the edition. Useful for various ecosystem tooling, such as automatic ESNext lint configuration if the `esnext` tag is present in the source edition tags.
	 * @example
	 * ``` json
	 * ["javascript", "esnext", "require"]
	 * ```
	 */
	tags?: string[]

	/**
	 * This field is used to specific which environments this edition supports.
	 * If `false` this edition does not any environment.
	 * If `deno` is a string, it should be a semver range of Deno versions that the edition targets.
	 * If `node` is a string, it should be a semver range of Node.js versions that the edition targets.
	 * If `browsers` is a string, it should be a [browserlist](https://github.com/browserslist/browserslist) value of the specific browser values the edition targets. If multiple engines are truthy, it indicates that this edition is compatible with those multiple environments.
	 * @example
	 * ``` json
	 * {
	 *   "deno": ">=1",
	 *   "node": ">=6",
	 *   "browsers": "defaults"
	 * }
	 * ```
	 */
	engines: Engines

	/** If this edition fails to load, then this property provides any accompanying information. */
	debugging?: Errtion
}

/** Editions should be ordered from most preferable first to least desirable last. The source edition should always be first, proceeded by compiled editions. */
export type Editions = Array<Edition>

export interface PathOptions {
	/** If provided, this edition entry is used instead of the default entry. */
	entry: string

	/** If provided, edition loading will be resolved against this. */
	cwd: string
}

export interface LoaderOptions extends Partial<PathOptions> {
	/**
	 * The method that will load the entry of the edition.
	 * For CJS files this should be set to the `require` method.
	 * For MJS files this should be set to `(path: string) => import(path)`.
	 */
	loader: <T>(this: Edition, path: string) => T
}

export interface RangeOptions {
	/** If `true`, then ranges such as `x || y` are changed to `>=x`. */
	broadenRange?: boolean
}

export interface VersionOptions extends RangeOptions {
	/** The versions of our current environment. */
	versions: Versions
}

export interface SolicitOptions extends LoaderOptions, VersionOptions {}

/**
 * Load the {@link Edition} with the loader.
 * @returns The result of the loaded edition.
 * @throws If failed to load, an error is thrown with the reason.
 */
export function loadEdition<T>(edition: Edition, opts: LoaderOptions): T {
	const entry = resolve(
		opts.cwd || '',
		edition.directory,
		opts.entry || edition.entry || ''
	)

	if (opts.loader == null) {
		throw errtion({
			message: `Could not load the edition [${edition.description}] as no loader was specified. This is probably due to a testing misconfiguration.`,
			code: 'editions-autoloader-loader-missing',
			level: 'fatal',
		})
	}

	try {
		return opts.loader.call(edition, entry) as T
	} catch (loadError: any) {
		// Note the error with more details
		throw errtion(
			{
				message: `Failed to load the entry [${entry}] of edition [${edition.description}].`,
				code: 'editions-autoloader-loader-failed',
				level: 'fatal',
			},
			loadError
		)
	}
}

/**
 * Verify the {@link Edition} has all the required properties.
 * @returns if valid
 * @throws if invalid
 */
export function isValidEdition(edition: Edition): true {
	if (
		!edition.description ||
		!edition.directory ||
		!edition.entry ||
		edition.engines == null
	) {
		throw errtion({
			message: `An edition must have its [description, directory, entry, engines] fields defined, yet all this edition defined were [${Object.keys(
				edition
			).join(', ')}]`,
			code: 'editions-autoloader-invalid-edition',
			level: 'fatal',
		})
	}

	// valid
	return true
}

/**
 * Is this {@link Edition} suitable for these versions?
 * @returns if compatible
 * @throws if incompatible
 */
export function isCompatibleVersion(
	range: Range,
	version: string,
	opts: RangeOptions
): true {
	// prepare
	const { broadenRange } = opts

	if (!version)
		throw errtion({
			message: `No version was specified to compare the range [${range}] against`,
			code: 'editions-autoloader-engine-version-missing',
			level: 'fatal',
		})

	if (range == null || range === '')
		throw errtion({
			message: `The edition range was not specified, so unable to compare against the version [${version}]`,
			code: 'editions-autoloader-engine-range-missing',
		})

	if (range === false)
		throw errtion({
			message: `The edition range does not support this engine`,
			code: 'editions-autoloader-engine-unsupported',
		})

	if (range === true) return true

	// original range
	try {
		if (matchRange(version, range)) return true
	} catch (error: any) {
		throw errtion(
			{
				message: `The range [${range}] was invalid, something is wrong with the Editions definition.`,
				code: 'editions-autoloader-invalid-range',
				level: 'fatal',
			},
			error
		)
	}

	// broadened range
	// https://github.com/bevry/editions/blob/master/HISTORY.md#v210-2018-november-15
	// If none of the editions for a package match the current node version, editions will try to find a compatible package by converting strict version ranges likes 4 || 6 || 8 || 10 to looser ones like >=4, and if that fails, then it will attempt to load the last edition for the environment.
	// This brings editions handling of engines closer in line with how node handles it, which is as a warning/recommendation, rather than a requirement/enforcement.
	// This has the benefit that edition authors can specify ranges as the specific versions that they have tested the edition against that pass, rather than having to omit that information for runtime compatibility.
	// As such editions will now automatically select the edition with guaranteed support for the environment, and if there are none with guaranteed support, then editions will select the one is most likely supported, and if there are none that are likely supported, then it will try the last edition, which should be the most compatible edition.
	// This is timely, as node v11 is now the version most developers use, yet if edition authors specified only LTS releases, then the editions autoloader would reject loading on v11, despite compatibility being likely with the most upper edition.
	// NOTE: That there is only one broadening chance per package, once a broadened edition has been returned, a load will be attempted, and if it fails, then the package failed. This is intentional.
	if (broadenRange === true) {
		// check if range can be broadened, validate it and extract
		const broadenedRangeRegex = /^\s*([0-9.]+)\s*(\|\|\s*[0-9.]+\s*)*$/
		const broadenedRangeMatch = range.match(broadenedRangeRegex)
		const lowestVersion: string =
			(broadenedRangeMatch && broadenedRangeMatch[1]) || ''
		// ^ can't do number conversion, as 1.1.1 is not a number
		// this also converts 0 to '' which is what we want for the next check

		// confirm the validation
		if (lowestVersion === '')
			throw errtion({
				message: `The range [${range}] is not able to be broadened, only ranges in format of [lowest] or [lowest || ... || ... ] can be broadened. Update the Editions definition and try again.`,
				code: 'editions-autoloader-unsupported-broadened-range',
				level: 'fatal',
			})

		// create the broadened range, and attempt that
		const broadenedRange = `>= ${lowestVersion}`
		try {
			if (matchRange(version, broadenedRange)) return true
		} catch (error: any) {
			throw errtion(
				{
					message: `The broadened range [${broadenedRange}] was invalid, something is wrong within Editions.`,
					code: 'editions-autoloader-invalid-broadened-range',
					level: 'fatal',
				},
				error
			)
		}

		// broadened range was incompatible
		throw errtion({
			message: `The edition range [${range}] does not support this engine version [${version}], even when broadened to [${broadenedRange}]`,
			code: 'editions-autoloader-engine-incompatible-broadened-range',
		})
	}

	// give up
	throw errtion({
		message: `The edition range [${range}] does not support this engine version [${version}]`,
		code: 'editions-autoloader-engine-incompatible-original',
	})
}

/**
 * Checks that the provided engines are compatible against the provided versions.
 * @returns if compatible
 * @throws if incompatible
 */
export function isCompatibleEngines(
	engines: Engines,
	opts: VersionOptions
): true {
	// PRepare
	const { versions } = opts

	// Check engines exist
	if (!engines) {
		throw errtion({
			message: `The edition had no engines to compare against the environment`,
			code: 'editions-autoloader-invalid-engines',
		})
	}

	// Check versions exist
	if (!versions) {
		throw errtion({
			message: `No versions were supplied to compare the engines against`,
			code: 'editions-autoloader-invalid-versions',
			level: 'fatal',
		})
	}

	// Check each version
	let compatible = false
	for (const key in engines) {
		if (engines.hasOwnProperty(key)) {
			// deno's std/node/process provides both `deno` and `node` keys
			// so we don't won't to compare node when it is actually deno
			if (key === 'node' && versions.deno) continue

			// prepare
			const engine = engines[key]
			const version = versions[key]

			// skip for engines this edition does not care about
			if (version == null) continue

			// check compatibility against all the provided engines it does care about
			try {
				isCompatibleVersion(engine, version, opts)
				compatible = true

				// if any incompatibility, it is thrown, so no need to set to false
			} catch (rangeError: any) {
				throw errtion(
					{
						message: `The engine [${key}] range of [${engine}] was not compatible against version [${version}].`,
						code: 'editions-autoloader-engine-error',
					},
					rangeError
				)
			}
		}
	}

	// if there were no matching engines, then throw
	if (!compatible) {
		throw errtion({
			message: `There were no supported engines in which this environment provides.`,
			code: 'editions-autoloader-engine-mismatch',
		})
	}

	// valid
	return true
}

/**
 * Checks that the {@link Edition} is compatible against the provided versions.
 * @returns if compatible
 * @throws if incompatible
 */
export function isCompatibleEdition(
	edition: Edition,
	opts: VersionOptions
): true {
	try {
		return isCompatibleEngines(edition.engines, opts)
	} catch (compatibleError: any) {
		throw errtion(
			{
				message: `The edition [${edition.description}] is not compatible with this environment.`,
				code: 'editions-autoloader-edition-incompatible',
			},
			compatibleError
		)
	}
}

/**
 * Determine which edition should be loaded.
 * If {@link VersionOptions.broadenRange} is unspecified (the default behavior), then we attempt to determine a suitable edition without broadening the range, and if that fails, then we try again with the range broadened.
 * @returns any suitable editions
 * @throws if no suitable editions
 */
export function determineEdition(
	editions: Editions,
	opts: VersionOptions
): Edition {
	// Prepare
	const { broadenRange } = opts

	// Check
	if (!editions || editions.length === 0) {
		throw errtion({
			message: 'No editions were specified.',
			code: 'editions-autoloader-editions-missing',
		})
	}

	// Cycle through the editions determining the above
	let failure: Errtion | null = null
	for (let i = 0; i < editions.length; ++i) {
		const edition = editions[i]
		try {
			isValidEdition(edition)
			isCompatibleEdition(edition, opts)

			// Success! Return the edition
			return edition
		} catch (error: any) {
			if (error.level === 'fatal') {
				throw errtion(
					{
						message: `Unable to determine a suitable edition due to failure.`,
						code: 'editions-autoloader-fatal',
						level: 'fatal',
					},
					error
				)
			} else if (failure) {
				failure = errtion(error, failure)
			} else {
				failure = error
			}
		}
	}

	// Report the failure from above
	if (failure) {
		// try broadened
		if (broadenRange == null)
			try {
				// return if broadening successfully returned an edition
				const broadenedEdition = determineEdition(editions, {
					...opts,
					broadenRange: true,
				})
				return {
					...broadenedEdition,
					// bubble the circumstances up in case the loading of the broadened edition fails and needs to be reported
					debugging: errtion({
						message: `The edition ${broadenedEdition.description} was selected to be force loaded as its range was broadened.`,
						code: 'editions-autoloader-attempt-broadened',
					}),
				}
			} catch (error: any) {
				throw errtion(
					{
						message: `Unable to determine a suitable edition, even after broadening.`,
						code: 'editions-autoloader-none-broadened',
					},
					error
				)
			}

		// fail
		throw errtion(
			{
				message: `Unable to determine a suitable edition, as none were suitable.`,
				code: 'editions-autoloader-none-suitable',
			},
			failure
		)
	}

	// this should never reach here
	throw errtion({
		message: `Unable to determine a suitable edition, as an unexpected pathway occurred.`,
		code: 'editions-autoloader-never',
	})
}

/**
 * Determine which edition should be loaded, and attempt to load it.
 * @returns the loaded result of the suitable edition
 * @throws if no suitable editions, or the edition failed to load
 */
export function solicitEdition<T>(editions: Editions, opts: SolicitOptions): T {
	const edition = determineEdition(editions, opts)
	try {
		return loadEdition<T>(edition, opts)
	} catch (error: any) {
		throw errtion(error, edition.debugging)
	}
}

/**
 * Cycle through the editions for a package, determine the compatible edition, and load it.
 * @returns the loaded result of the suitable edition
 * @throws if no suitable editions, or if the edition failed to load
 */
export function requirePackage<T>(
	cwd: PathOptions['cwd'],
	loader: LoaderOptions['loader'],
	entry: PathOptions['entry']
): T {
	const packagePath = resolve(cwd || '', 'package.json')
	try {
		// load editions
		const { editions } = JSON.parse(readFileSync(packagePath, 'utf8'))

		// load edition
		return solicitEdition<T>(editions, {
			versions: processVersions as any as Versions,
			cwd,
			loader,
			entry,
		})
	} catch (error: any) {
		throw errtion(
			{
				message: `Unable to determine a suitable edition for the package [${packagePath}] and entry [${entry}]`,
				code: 'editions-autoloader-package',
			},
			error
		)
	}
}
