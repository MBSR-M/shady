#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
import pandas as pd
import os
import subprocess
import sys

# File to store tasks
task_file = "tasks.csv"

# Initialize FastAPI app
app = FastAPI()


# Load tasks from the file
def load_tasks():
    if os.path.exists(task_file):
        return pd.read_csv(task_file)
    else:
        return pd.DataFrame(columns=["Task", "Status"])


# Save tasks to the file
def save_tasks(tasks_df):
    tasks_df.to_csv(task_file, index=False)


# Pydantic model for task input
class Task(BaseModel):
    task: str
    status: str = "Pending"


@app.get("/tasks", status_code=status.HTTP_200_OK)
def get_tasks():
    """Retrieve all tasks."""
    tasks_df = load_tasks()
    if tasks_df.empty:
        return []
    return tasks_df.to_dict(orient="records")


@app.post("/tasks", status_code=status.HTTP_201_CREATED)
def add_task(task: Task):
    """Add a new task."""
    if not task.task.strip():
        raise HTTPException(status_code=400, detail="Task cannot be empty.")

    tasks_df = load_tasks()
    tasks_df = tasks_df.append({"Task": task.task, "Status": task.status}, ignore_index=True)
    save_tasks(tasks_df)
    return {"message": "Task added successfully."}


@app.delete("/tasks/{task_id}", status_code=status.HTTP_200_OK)
def delete_task(task_id: int):
    """Delete a task by ID."""
    tasks_df = load_tasks()
    if task_id < 0 or task_id >= len(tasks_df):
        raise HTTPException(status_code=404, detail="Task not found.")

    tasks_df = tasks_df.drop(task_id).reset_index(drop=True)
    save_tasks(tasks_df)
    return {"message": "Task deleted successfully."}


@app.put("/tasks/{task_id}", status_code=status.HTTP_200_OK)
def update_task_status(task_id: int, status: str):
    """Update the status of a task by ID."""
    tasks_df = load_tasks()
    if task_id < 0 or task_id >= len(tasks_df):
        raise HTTPException(status_code=404, detail="Task not found.")

    tasks_df.at[task_id, "Status"] = status
    save_tasks(tasks_df)
    return {"message": "Task status updated successfully."}

