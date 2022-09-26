from requests_mock import Mocker
from howfairis.checker import Checker
from howfairis.repo import Repo
from howfairis.workarounds.github_caching import github_caching_check


def initialize_checker(requests_mock: Mocker, capsys):
    owner = "fair-software"
    repo_string = "howfairis"
    filename = "README.rst"
    url = "https://github.com/{0}/{1}".format(owner, repo_string)
    requests_mock.get("https://raw.githubusercontent.com/{0}/{1}/main/{2}".format(owner, repo_string, filename),
                      json={}, status_code=200)
    requests_mock.get("https://raw.githubusercontent.com/{0}/{1}/main/.howfairis.yml".format(owner, repo_string),
                      json={}, status_code=200)
    repo = Repo(url, branch="main")
    checker = Checker(repo)
    capsys.readouterr()
    return checker


def test_github_caching_should_warn(requests_mock: Mocker, capsys):
    checker = initialize_checker(requests_mock, capsys)
    requests_mock.get("{0}/commits".format(checker.repo.api), json=["nonzero array length should trigger warning"], status_code=200)
    github_caching_check(checker)
    actual_out_err = capsys.readouterr()
    expected_out = (("Warning: Your {0} was updated less than 5 minutes ago. The effects of this update are not " +
                     "visible yet in the calculated compliance.\n").format(checker.readme.filename))
    assert actual_out_err[0] == expected_out


def test_github_caching_should_not_warn(requests_mock: Mocker, capsys):
    checker = initialize_checker(requests_mock, capsys)
    requests_mock.get("{0}/commits".format(checker.repo.api), json=[], status_code=200)
    github_caching_check(checker)
    actual_out_err = capsys.readouterr()
    expected_out = ""
    assert actual_out_err[0] == expected_out


def test_github_caching_without_readme(requests_mock: Mocker, capsys):
    checker = initialize_checker(requests_mock, capsys)
    requests_mock.get("{0}/commits".format(checker.repo.api), json={}, status_code=404)
    github_caching_check(checker)
    actual_out_err = capsys.readouterr()
    expected_out = ""
    assert actual_out_err[0] == expected_out
