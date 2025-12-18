package metadata

generated: components: transforms: matchy: configuration: {
	databases: {
		description: """
			Map of database ID to database configuration

			Each database will be loaded and queried for matches. Results
			will be tagged with the database ID for downstream filtering.
			"""
		required: false
		type: object: options: "*": {
			description: "Configuration for a matchy database."
			required:    true
			type: object: options: {
				auto_reload: {
					description: """
						Enable automatic reload when the database file changes

						When enabled, the database will watch its source file and automatically
						reload when changes are detected. All queries transparently use the latest
						version with zero downtime. Uses lock-free atomic swapping for minimal overhead.
						"""
					required: false
					type: bool: {}
				}
				auto_update: {
					description: """
						Enable automatic updates from the database's embedded update URL

						When enabled, the database will periodically check its embedded URL for updates
						using HTTP conditional GET (ETag). Updates are downloaded to a cache directory,
						leaving the original file untouched. The database must have an update URL embedded
						in its metadata (set during build with `matchy build --update-url`).
						"""
					required: false
					type: bool: {}
				}
				update_interval_secs: {
					description: """
						How often to check for remote updates (in seconds)

						Only used when `auto_update` is enabled. Default: 3600 (1 hour).
						"""
					required: false
					type: uint: {}
				}
				cache_dir: {
					description: """
						Directory to cache downloaded database updates

						Only used when `auto_update` is enabled. Default: system cache directory
						(~/.cache/matchy/ on Unix, %LOCALAPPDATA%\\matchy\\ on Windows).
						"""
					required: false
					type: string: {}
				}
				cache_capacity: {
					description: """
						LRU cache capacity for query results

						Set to 0 to disable caching. Default: 10000 entries.
						"""
					required: false
					type: uint: {}
				}
				path: {
					description: "Path to the matchy database file (.mxy or .mmdb)"
					required:    true
					type: string: {}
				}
			}
		}
	}
	extract: {
		description: """
			Extraction configuration (optional)

			If specified, the transform will extract indicators (IPs, domains, etc.)
			from the specified field before matching. If not specified, the transform
			will attempt to match the entire field value.
			"""
		required: false
		type: object: options: {
			bitcoin: {
				description: "Extract Bitcoin addresses from events"
				required:    false
				type: bool: default: false
			}
			domains: {
				description: "Extract domain names from events"
				required:    false
				type: bool: default: true
			}
			emails: {
				description: "Extract email addresses from events"
				required:    false
				type: bool: default: false
			}
			ethereum: {
				description: "Extract Ethereum addresses from events"
				required:    false
				type: bool: default: false
			}
			hashes: {
				description: "Extract file hashes (MD5, SHA1, SHA256) from events"
				required:    false
				type: bool: default: true
			}
			ipv4: {
				description: "Extract IPv4 addresses from events"
				required:    false
				type: bool: default: true
			}
			ipv6: {
				description: "Extract IPv6 addresses from events"
				required:    false
				type: bool: default: true
			}
			monero: {
				description: "Extract Monero addresses from events"
				required:    false
				type: bool: default: false
			}
		}
	}
	match_field: {
		description: "Optional field to set as boolean match flag (e.g., \".is_threat\")"
		required:    false
		type: string: {}
	}
	output_field: {
		description: "Field to write match results to (default: \".matchy_results\")"
		required:    false
		type: string: default: ".matchy_results"
	}
	source_field: {
		description: "Field to read for matching (default: \"message\")"
		required:    false
		type: string: default: "message"
	}
}
