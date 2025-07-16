import pyfiglet
import typer

def display_banner():
    banner_text = pyfiglet.figlet_format("CloudCastle")
    typer.echo(banner_text)
