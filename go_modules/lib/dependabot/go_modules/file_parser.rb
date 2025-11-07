# typed: strict
# frozen_string_literal: true

require "sorbet-runtime"

require "open3"
require "dependabot/dependency"
require "dependabot/file_parsers/base/dependency_set"
require "dependabot/go_modules/path_converter"
require "dependabot/go_modules/replace_stubber"
require "dependabot/errors"
require "dependabot/file_parsers"
require "dependabot/file_parsers/base"
require "dependabot/go_modules/version"
require "dependabot/go_modules/language"
require "dependabot/go_modules/package_manager"

module Dependabot
  module GoModules
    class FileParser < Dependabot::FileParsers::Base
      extend T::Sig

      # NOTE: repo_contents_path is typed as T.nilable(String) to maintain
      # compatibility with the base FileParser class signature. However,
      # we validate it's not nil at runtime since it's always required in production.
      sig do
        params(
          dependency_files: T::Array[Dependabot::DependencyFile],
          source: T.nilable(Dependabot::Source),
          repo_contents_path: T.nilable(String),
          credentials: T::Array[Dependabot::Credential],
          reject_external_code: T::Boolean,
          options: T::Hash[Symbol, T.untyped]
        ).void
      end
      def initialize(
        dependency_files:,
        source: nil,
        repo_contents_path: nil,
        credentials: [],
        reject_external_code: false,
        options: {}
      )
        super

        raise ArgumentError, "repo_contents_path is required" if repo_contents_path.nil?

        set_go_environment_variables
      end

      sig { override.returns(T::Array[Dependabot::Dependency]) }
      def parse
        dependency_set = Dependabot::FileParsers::Base::DependencySet.new

        parse_required_packages(dependency_set)
        parse_tool_packages(dependency_set)

        dependency_set.dependencies
      end

      sig { returns(Ecosystem) }
      def ecosystem
        @ecosystem ||= T.let(
          begin
            Ecosystem.new(
              name: ECOSYSTEM,
              package_manager: package_manager,
              language: language
            )
          end,
          T.nilable(Dependabot::Ecosystem)
        )
      end

      # Utility method to allow collaborators to check other go commands inside the parsed project's context
      sig { params(command: String).returns(String) }
      def run_in_parsed_context(command)
        SharedHelpers.in_a_temporary_repo_directory(T.must(source&.directory), repo_contents_path) do |path|
          # Create a fake empty module for local modules that are not inside the repository.
          # This allows us to run go commands that require all modules to be present.
          local_replacements.each do |_, stub_path|
            FileUtils.mkdir_p(stub_path)
            FileUtils.touch(File.join(stub_path, "go.mod"))
          end

          File.write("go.mod", go_mod_content)

          stdout, stderr, status = Open3.capture3(command)
          handle_parser_error(path, stderr) unless status.success?

          stdout
        end
      end

      private

      sig { params(dependency_set: Dependabot::FileParsers::Base::DependencySet).void }
      def parse_required_packages(dependency_set)
        # Collect tool package paths and their parent modules to avoid duplicates
        tool_paths = tool_packages.map { |pkg| pkg["Path"] }

        # Also collect the module paths that provide these tools
        tool_module_paths = tool_paths.flat_map do |tool_path|
          required_packages
            .select { |pkg| tool_path == pkg["Path"] || tool_path.start_with?("#{pkg['Path']}/") }
            .map { |pkg| pkg["Path"] }
        end.uniq

        required_packages.each do |hsh|
          # Skip if this is a tool dependency or its module (will be added separately)
          next if tool_paths.include?(hsh["Path"]) || tool_module_paths.include?(hsh["Path"])
          next if skip_dependency?(hsh)

          dep = dependency_from_details(hsh)
          dependency_set << dep
        end
      end

      sig { params(dependency_set: Dependabot::FileParsers::Base::DependencySet).void }
      def parse_tool_packages(dependency_set)
        tool_packages.each do |hsh|
          next if skip_dependency?(hsh)

          dep = tool_dependency_from_details(hsh)
          dependency_set << dep
        end
      end

      sig { void }
      def set_go_environment_variables
        set_goenv_variable
        set_goproxy_variable
        set_goprivate_variable
      end

      sig { void }
      def set_goenv_variable
        return unless go_env

        env_file = T.must(go_env)
        File.write(env_file.name, env_file.content)
        ENV["GOENV"] = Pathname.new(env_file.name).realpath.to_s
      end

      sig { void }
      def set_goprivate_variable
        return if go_env&.content&.include?("GOPRIVATE")
        return if go_env&.content&.include?("GOPROXY")
        return if goproxy_credentials.any?

        goprivate = options.fetch(:goprivate, "*")
        ENV["GOPRIVATE"] = goprivate if goprivate
      end

      sig { void }
      def set_goproxy_variable
        return if go_env&.content&.include?("GOPROXY")
        return if goproxy_credentials.empty?

        urls = goproxy_credentials.filter_map { |cred| cred["url"] }
        ENV["GOPROXY"] = "#{urls.join(',')},direct"
      end

      sig { returns(T::Array[Dependabot::Credential]) }
      def goproxy_credentials
        @goproxy_credentials ||= T.let(
          credentials.select do |cred|
            cred["type"] == "goproxy_server"
          end,
          T.nilable(T::Array[Dependabot::Credential])
        )
      end

      sig { returns(Ecosystem::VersionManager) }
      def package_manager
        @package_manager ||= T.let(
          PackageManager.new(T.must(go_toolchain_version)),
          T.nilable(Dependabot::GoModules::PackageManager)
        )
      end

      sig { returns(T.nilable(Ecosystem::VersionManager)) }
      def language
        @language ||= T.let(
          go_version ? Language.new(T.must(go_version)) : nil,
          T.nilable(Dependabot::GoModules::Language)
        )
      end

      sig { returns(T.nilable(String)) }
      def go_version
        @go_version ||= T.let(
          go_mod&.content&.match(/^go\s(\d+\.\d+(.\d+)*)/)&.captures&.first,
          T.nilable(String)
        )
      end

      sig { returns(T.nilable(String)) }
      def go_toolchain_version
        @go_toolchain_version ||= T.let(
          begin
            # Checks version based on the GOTOOLCHAIN in ENV
            version = SharedHelpers.run_shell_command("go version")
            version.match(/go\s*(\d+\.\d+(.\d+)*)/)&.captures&.first
          end,
          T.nilable(String)
        )
      end

      sig { returns(T.nilable(Dependabot::DependencyFile)) }
      def go_mod
        @go_mod ||= T.let(get_original_file("go.mod"), T.nilable(Dependabot::DependencyFile))
      end

      sig { returns(T.nilable(Dependabot::DependencyFile)) }
      def go_env
        @go_env ||= T.let(get_original_file("go.env"), T.nilable(Dependabot::DependencyFile))
      end

      sig { override.void }
      def check_required_files
        raise "No go.mod!" unless go_mod
      end

      sig { params(details: T::Hash[String, T.untyped]).returns(Dependabot::Dependency) }
      def dependency_from_details(details)
        source = { type: "default", source: details["Path"] }
        version = details["Version"]&.sub(/^v?/, "")

        reqs = [{
          requirement: details["Version"],
          file: go_mod&.name,
          source: source,
          groups: []
        }]

        Dependency.new(
          name: details["Path"],
          version: version,
          requirements: details["Indirect"] ? [] : reqs,
          package_manager: "go_modules"
        )
      end

      sig { params(details: T::Hash[String, T.untyped]).returns(Dependabot::Dependency) }
      def tool_dependency_from_details(details)
        # Tool dependencies are stored in the Tool array, but their versions
        # are tracked in the Require array (as indirect dependencies).
        # We need to find the corresponding version from required_packages.
        tool_path = details["Path"]

        # Tool paths can be subpackages (e.g., golang.org/x/tools/cmd/stringer)
        # but versions are tracked at the module level (e.g., golang.org/x/tools)
        # Find the module that contains this tool
        version_info = required_packages.find do |pkg|
          # Check if the tool path starts with the package path
          # This handles cases where tool is a subpackage
          tool_path == pkg["Path"] || tool_path.start_with?("#{pkg['Path']}/")
        end

        source = { type: "default", source: tool_path }
        version = version_info&.dig("Version")&.sub(/^v?/, "")

        reqs = if version_info
                 [{
                   requirement: version_info["Version"],
                   file: go_mod&.name,
                   source: source,
                   groups: ["tool"]
                 }]
               else
                 []
               end

        Dependency.new(
          name: tool_path,
          version: version,
          requirements: reqs,
          package_manager: "go_modules",
          metadata: { dependency_type: "tool" }
        )
      end

      sig { returns(T::Array[T::Hash[String, T.untyped]]) }
      def required_packages
        @required_packages ||=
          T.let(
            JSON.parse(run_in_parsed_context("go mod edit -json"))["Require"] || [],
            T.nilable(T::Array[T::Hash[String, T.untyped]])
          )
      end

      sig { returns(T::Array[T::Hash[String, T.untyped]]) }
      def tool_packages
        @tool_packages ||=
          T.let(
            JSON.parse(run_in_parsed_context("go mod edit -json"))["Tool"] || [],
            T.nilable(T::Array[T::Hash[String, T.untyped]])
          )
      end

      sig { returns(T::Hash[String, String]) }
      def local_replacements
        @local_replacements ||=
          # Find all the local replacements, and return them with a stub path
          # we can use in their place. Using generated paths is safer as it
          # means we don't need to worry about references to parent
          # directories, etc.
          T.let(
            ReplaceStubber.new(T.must(repo_contents_path)).stub_paths(manifest, go_mod&.directory),
            T.nilable(T::Hash[String, String])
          )
      end

      sig { returns(T::Hash[String, T.untyped]) }
      def manifest
        @manifest ||=
          T.let(
            SharedHelpers.in_a_temporary_directory do |path|
              File.write("go.mod", go_mod&.content)

              # Parse the go.mod to get a JSON representation of the replace
              # directives
              command = "go mod edit -json"

              stdout, stderr, status = Open3.capture3(command)
              handle_parser_error(path, stderr) unless status.success?

              JSON.parse(stdout)
            end,
            T.nilable(T::Hash[String, T.untyped])
          )
      end

      sig { returns(T.nilable(String)) }
      def go_mod_content
        local_replacements.reduce(go_mod&.content) do |body, (path, stub_path)|
          body&.sub(path, stub_path)
        end
      end

      sig { params(path: T.any(Pathname, String), stderr: String).returns(T.noreturn) }
      def handle_parser_error(path, stderr)
        msg = stderr.gsub(path.to_s, "").strip
        raise Dependabot::DependencyFileNotParseable.new(T.must(go_mod).path, msg)
      end

      sig { params(dep: T::Hash[String, T.untyped]).returns(T::Boolean) }
      def skip_dependency?(dep)
        # Updating replaced dependencies is not supported
        return true if dependency_is_replaced(dep)

        path_uri = URI.parse("https://#{dep['Path']}")
        !path_uri.host&.include?(".")
      rescue URI::InvalidURIError
        false
      end

      sig { params(details: T::Hash[String, T.untyped]).returns(T::Boolean) }
      def dependency_is_replaced(details)
        # Mark dependency as replaced if the requested dependency has a
        # "replace" directive and that either has the same version, or no
        # version mentioned. This mimics the behaviour of go get -u, and
        # prevents that we change dependency versions without any impact since
        # the actual version that is being imported is defined by the replace
        # directive.
        if manifest["Replace"]
          dep_replace = manifest["Replace"].find do |replace|
            replace["Old"]["Path"] == details["Path"] &&
              (!replace["Old"]["Version"] || replace["Old"]["Version"] == details["Version"])
          end

          return true if dep_replace
        end
        false
      end
    end
  end
end

Dependabot::FileParsers
  .register("go_modules", Dependabot::GoModules::FileParser)
