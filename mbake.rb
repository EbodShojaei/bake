class Mbake < Formula
  include Language::Python::Virtualenv

  desc "Python-based Makefile formatter and linter"
  homepage "https://github.com/ebodshojaei/bake"
  url "https://github.com/ebodshojaei/bake/archive/v1.0.0.tar.gz"
  sha256 "SHA256_PLACEHOLDER"
  license "MIT"

  depends_on "python@3.9"

  resource "rich" do
    url "https://files.pythonhosted.org/packages/source/r/rich/rich-13.9.4.tar.gz"
    sha256 "439594978a49a09530cff7ebc4b5c7103ef57baf48d5ea3184f21d9a2befa098"
  end

  resource "typer" do
    url "https://files.pythonhosted.org/packages/source/t/typer/typer-0.15.2.tar.gz"
    sha256 "bbc73c88b66d70e5e37797d77d1700a4b2e11f0b82a34eefca43c38ff0b35e82"
  end

  resource "tomli" do
    url "https://files.pythonhosted.org/packages/source/t/tomli/tomli-2.2.1.tar.gz"
    sha256 "cd45e1dc79c835ce60f7404ec8119f2eb06d38b1deba146f07ced3bbc44505ff"
  end

  resource "click" do
    url "https://files.pythonhosted.org/packages/source/c/click/click-8.1.8.tar.gz"
    sha256 "ed53c9d8990d83c2a27deae68e4ee337473f6330c040a31d4225c9574d16096a"
  end

  resource "typing-extensions" do
    url "https://files.pythonhosted.org/packages/source/t/typing-extensions/typing_extensions-4.12.2.tar.gz"
    sha256 "1a7ead55c7e559dd4dee8856e3a88b41225abfe1ce8df57b7c13915fe121ffb8"
  end

  resource "shellingham" do
    url "https://files.pythonhosted.org/packages/source/s/shellingham/shellingham-1.5.4.tar.gz"
    sha256 "8dbca0739d487e5bd35ab3ca4b36e11c4078f3a234bfce294b0a0291363404de"
  end

  resource "markdown-it-py" do
    url "https://files.pythonhosted.org/packages/source/m/markdown-it-py/markdown_it_py-3.0.0.tar.gz"
    sha256 "e3f60a94fa066dc52ec76661e37c851cb232d92f9886b15cb560aaada2df8feb"
  end

  resource "pygments" do
    url "https://files.pythonhosted.org/packages/source/p/pygments/pygments-2.19.1.tar.gz"
    sha256 "61c16a2b780ded5de8cbe73d27ebf89bd891d4dfe4b7cc8cdf2b3f8b0ea4b59e"
  end

  resource "mdurl" do
    url "https://files.pythonhosted.org/packages/source/m/mdurl/mdurl-0.1.2.tar.gz"
    sha256 "bb413d29f5eea38f31dd4754dd7377d4465116fb207585f97bf925588687c1ba"
  end

  def install
    virtualenv_install_with_resources
  end

  test do
    (testpath/"Makefile").write <<~EOS
      CC=gcc
      CFLAGS=-Wall
      
      all:target
      	echo "Building"
      
      clean:
      	rm -f target
    EOS

    (testpath/".bake.toml").write <<~EOS
      [formatter]
      use_tabs = true
      tab_width = 4
      space_around_assignment = true
      space_before_colon = false
      space_after_colon = true
      normalize_line_continuations = true
      max_line_length = 120
      group_phony_declarations = true
      phony_at_top = true
      remove_trailing_whitespace = true
      ensure_final_newline = true
      normalize_empty_lines = true
      max_consecutive_empty_lines = 2
      
      debug = false
      verbose = false
    EOS

    # Test that bake can check formatting
    system "#{bin}/bake", "--check", "Makefile"
    
    # Test that bake can format the file
    system "#{bin}/bake", "Makefile"
    
    # Verify the file was formatted correctly
    output = (testpath/"Makefile").read
    assert_match(/CC := gcc/, output)
    assert_match(/CFLAGS := -Wall/, output)
    assert_match(/all: target/, output)
  end
end 