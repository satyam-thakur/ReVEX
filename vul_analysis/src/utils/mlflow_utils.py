import logging
import os

logger = logging.getLogger(__name__)

def setup_mlflow(tracking_uri: str = None, experiment_name: str = "ContainerSecurity_Analysis", log_optimizer: bool = False):
    """
    Configures MLflow tracing for DSPy.
    
    Args:
        tracking_uri: The URI of the MLflow tracking server. If None, defaults to local ./mlruns
        experiment_name: The name of the experiment to log runs to.
        log_optimizer: If True, enable optimizer tracking (log_compiles, log_evals, log_traces_from_compile)
    """
    try:
        import mlflow
        
        # Set the tracking URI if provided
        if tracking_uri:
            mlflow.set_tracking_uri(tracking_uri)
        
        # Set the experiment
        mlflow.set_experiment(experiment_name)
        
        # Enable DSPy autologging
        # This requires mlflow >= 2.18.0
        if hasattr(mlflow, 'dspy'):
            if log_optimizer:
                # Full optimizer tracking for MIPROv2
                mlflow.dspy.autolog(
                    log_compiles=True,
                    log_evals=True,
                    log_traces_from_compile=True
                )
                logger.info(f"MLflow optimizer tracking enabled. Experiment: {experiment_name}")
            else:
                mlflow.dspy.autolog()
                logger.info(f"MLflow tracing enabled. Experiment: {experiment_name}")
        else:
            logger.warning("mlflow.dspy attribute not found. Ensure you have mlflow>=2.18.0 installed.")
            
    except ImportError:
        logger.warning("MLflow not installed. Tracing will be disabled.")
    except Exception as e:
        logger.error(f"Failed to setup MLflow: {e}")
        logger.warning("Continuing without MLflow tracing...")

