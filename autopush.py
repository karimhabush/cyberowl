import git
import os
from dotenv import load_dotenv
load_dotenv()

GITHUB_ACCESS_TOKEN = os.environ.get("GITHUB_ACCESS_TOKEN")
GITHUB_USERNAME = os.environ.get("GITHUB_USERNAME")

REMOTE = f"https://{GITHUB_USERNAME}:{GITHUB_ACCESS_TOKEN}@github.com/{GITHUB_ACCESS_TOKEN}/cyberowl.git"
CLONE_TO = os.getcwd()
try:
    git.Repo.clone_from(REMOTE, CLONE_TO)
except Exception:
    print("[INFO]: Already cloned")

# make sure .git folder is properly configured
PATH_OF_GIT_REPO = os.getcwd() + r"/cyberowl/.git"
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
