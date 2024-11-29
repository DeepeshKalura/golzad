import subprocess 
import click
import os

@click.group()
def cli():
    """golzad is create personalized cloud storage server."""
    pass

@cli.command()
@click.option('--name', default='app', help='Name of the project folder.')
def init(name):
    # Check if the folder already exists
    if not os.path.exists(name):
        # Create the folder
        os.makedirs(name)
        print(f"Folder '{name}' has been created.")
    else:
        print(f"Folder '{name}' already exists.")

if __name__ == '__main__':
    cli()