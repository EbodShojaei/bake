# fish completion for bake

complete -c bake -n "__fish_use_subcommand" -s h -l help -d "Show this help message and exit"
complete -c bake -n "__fish_use_subcommand" -l version -d "Show version and exit"

complete -c bake -n "__fish_use_subcommand" -a init -d "Initialize configuration file with defaults"
complete -c bake -n "__fish_use_subcommand" -a config -d "Show current configuration"
complete -c bake -n "__fish_use_subcommand" -a validate -d "Validate Makefile syntax"
complete -c bake -n "__fish_use_subcommand" -a format -d "Format Makefiles"
complete -c bake -n "__fish_use_subcommand" -a update -d "Update mbake to the latest version from PyPI"
complete -c bake -n "__fish_use_subcommand" -a completions -d "Generate shell completion scripts"

# init command
complete -c bake -n "__fish_seen_subcommand_from init" -l force -d "Overwrite existing config"
complete -c bake -n "__fish_seen_subcommand_from init" -l config -r -d "Path to configuration file"
complete -c bake -n "__fish_seen_subcommand_from init" -s h -l help -d "Show this help message and exit"

# config command
complete -c bake -n "__fish_seen_subcommand_from config" -l path -d "Show config file path"
complete -c bake -n "__fish_seen_subcommand_from config" -l config -r -d "Path to configuration file"
complete -c bake -n "__fish_seen_subcommand_from config" -s h -l help -d "Show this help message and exit"

# validate command
complete -c bake -n "__fish_seen_subcommand_from validate" -l config -r -d "Path to configuration file"
complete -c bake -n "__fish_seen_subcommand_from validate" -l verbose -s v -d "Enable verbose output"
complete -c bake -n "__fish_seen_subcommand_from validate" -s h -l help -d "Show this help message and exit"

# format command
complete -c bake -n "__fish_seen_subcommand_from format" -l check -s c -d "Check formatting without changes"
complete -c bake -n "__fish_seen_subcommand_from format" -l diff -s d -d "Show diff of changes"
complete -c bake -n "__fish_seen_subcommand_from format" -l verbose -s v -d "Enable verbose output"
complete -c bake -n "__fish_seen_subcommand_from format" -l debug -d "Enable debug output"
complete -c bake -n "__fish_seen_subcommand_from format" -l config -r -d "Path to configuration file"
complete -c bake -n "__fish_seen_subcommand_from format" -l backup -s b -d "Create backup files"
complete -c bake -n "__fish_seen_subcommand_from format" -l validate -d "Validate syntax after formatting"
complete -c bake -n "__fish_seen_subcommand_from format" -s h -l help -d "Show this help message and exit"

# update command
complete -c bake -n "__fish_seen_subcommand_from update" -l force -d "Force update even if up to date"
complete -c bake -n "__fish_seen_subcommand_from update" -l check -d "Only check, don't update"
complete -c bake -n "__fish_seen_subcommand_from update" -l yes -s y -d "Skip confirmation prompt"
complete -c bake -n "__fish_seen_subcommand_from update" -s h -l help -d "Show this help message and exit"

# completions command
complete -c bake -n "__fish_seen_subcommand_from completions" -a "bash zsh fish" -d "Shell type"
complete -c bake -n "__fish_seen_subcommand_from completions" -s h -l help -d "Show this help message and exit"

# Also add completions for mbake alias
complete -c mbake -n "__fish_use_subcommand" -s h -l help -d "Show this help message and exit"
complete -c mbake -n "__fish_use_subcommand" -l version -d "Show version and exit"

complete -c mbake -n "__fish_use_subcommand" -a init -d "Initialize configuration file with defaults"
complete -c mbake -n "__fish_use_subcommand" -a config -d "Show current configuration"
complete -c mbake -n "__fish_use_subcommand" -a validate -d "Validate Makefile syntax"
complete -c mbake -n "__fish_use_subcommand" -a format -d "Format Makefiles"
complete -c mbake -n "__fish_use_subcommand" -a update -d "Update mbake to the latest version from PyPI"
complete -c mbake -n "__fish_use_subcommand" -a completions -d "Generate shell completion scripts"

# Copy all the subcommand completions for mbake
complete -c mbake -n "__fish_seen_subcommand_from init" -l force -d "Overwrite existing config"
complete -c mbake -n "__fish_seen_subcommand_from init" -l config -r -d "Path to configuration file"
complete -c mbake -n "__fish_seen_subcommand_from init" -s h -l help -d "Show this help message and exit"

complete -c mbake -n "__fish_seen_subcommand_from config" -l path -d "Show config file path"
complete -c mbake -n "__fish_seen_subcommand_from config" -l config -r -d "Path to configuration file"
complete -c mbake -n "__fish_seen_subcommand_from config" -s h -l help -d "Show this help message and exit"

complete -c mbake -n "__fish_seen_subcommand_from validate" -l config -r -d "Path to configuration file"
complete -c mbake -n "__fish_seen_subcommand_from validate" -l verbose -s v -d "Enable verbose output"
complete -c mbake -n "__fish_seen_subcommand_from validate" -s h -l help -d "Show this help message and exit"

complete -c mbake -n "__fish_seen_subcommand_from format" -l check -s c -d "Check formatting without changes"
complete -c mbake -n "__fish_seen_subcommand_from format" -l diff -s d -d "Show diff of changes"
complete -c mbake -n "__fish_seen_subcommand_from format" -l verbose -s v -d "Enable verbose output"
complete -c mbake -n "__fish_seen_subcommand_from format" -l debug -d "Enable debug output"
complete -c mbake -n "__fish_seen_subcommand_from format" -l config -r -d "Path to configuration file"
complete -c mbake -n "__fish_seen_subcommand_from format" -l backup -s b -d "Create backup files"
complete -c mbake -n "__fish_seen_subcommand_from format" -l validate -d "Validate syntax after formatting"
complete -c mbake -n "__fish_seen_subcommand_from format" -s h -l help -d "Show this help message and exit"

complete -c mbake -n "__fish_seen_subcommand_from update" -l force -d "Force update even if up to date"
complete -c mbake -n "__fish_seen_subcommand_from update" -l check -d "Only check, don't update"
complete -c mbake -n "__fish_seen_subcommand_from update" -l yes -s y -d "Skip confirmation prompt"
complete -c mbake -n "__fish_seen_subcommand_from update" -s h -l help -d "Show this help message and exit"

complete -c mbake -n "__fish_seen_subcommand_from completions" -a "bash zsh fish" -d "Shell type"
complete -c mbake -n "__fish_seen_subcommand_from completions" -s h -l help -d "Show this help message and exit" 