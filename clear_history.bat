@echo off
REM Step 1: Checkout/create orphan branch named 'latest_branch'
echo Checking out orphan branch 'latest_branch'...
git checkout --orphan latest_branch

REM Step 2: Add all files to the newly created branch
echo Adding all files to the branch...
git add -A

REM Step 3: Commit the changes
echo Committing changes...
git commit -am "Initial Commit"

REM Step 4: Delete the main (default) branch
echo Deleting the 'main' branch locally...
git branch -D main

REM Step 5: Rename the current branch to 'main'
echo Renaming the current branch to 'main'...
git branch -m main

REM Step 6: Force update your remote repository
echo Force-pushing the changes to the remote repository...
git push -f origin main

echo Process completed successfully.
pause
