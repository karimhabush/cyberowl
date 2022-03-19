import git
import os
from dotenv import load_dotenv
load_dotenv()

GITHUB_ACCESS_TOKEN = os.environ.get("GITHUB_ACCESS_TOKEN")
GITHUB_USERNAME = os.environ.get("GITHUB_USERNAME")

try:
    git.Git("./").clone(os.environ.get("GITHUB_REPO"))
except Exception:
    print("[INFO]: Already cloned")

# make sure .git folder is properly configured
PATH_OF_GIT_REPO = os.getcwd() + r"/cyberowl/.git"
print(PATH_OF_GIT_REPO)
COMMIT_MESSAGE = 'This is a commit from heroku! time to merge hh !'
FILE_TO_ADD = "README.md"
BRANCH = "dev"


def git_push():
    repo = git.Repo(PATH_OF_GIT_REPO)
    repo.git.checkout(BRANCH)
    repo.git.add(FILE_TO_ADD)
    repo.index.commit(COMMIT_MESSAGE)
    origin = repo.remote(name='origin')
    origin.push(refspec="dev:dev")
