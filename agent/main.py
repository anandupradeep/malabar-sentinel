"""Agent entry point — launches GUI."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
from agent.gui import main
 
if __name__ == "__main__":
    main()