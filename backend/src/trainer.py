import os
import json
import torch
import numpy as np
from datasets import Dataset
from transformers import (
    AutoTokenizer, 
    AutoModelForSequenceClassification, 
    TrainingArguments, 
    Trainer
)
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

def train_model(data_path="f:/Fullbright Scholarship/X-CloudSentinel/backend/data/training_data.json"):
    print(f"Loading data from {data_path}...")
    with open(data_path, 'r') as f:
        raw_data = json.load(f)
    
    # Map labels to IDs
    label_map = {"Secure": 0, "Misconfigured": 1, "SecretLeakage": 2, "HighRisk": 3}
    texts = [item['text'] for item in raw_data]
    labels = [label_map[item['label']] for item in raw_data]
    
    # Split data
    train_texts, val_texts, train_labels, val_labels = train_test_split(
        texts, labels, test_size=0.2, random_state=42
    )
    
    # Load tokenizer
    model_name = "distilbert-base-uncased"
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    
    def tokenize_function(examples):
        return tokenizer(examples["text"], padding="max_length", truncation=True, max_length=512)
    
    # Create datasets
    train_dataset = Dataset.from_dict({"text": train_texts, "label": train_labels})
    val_dataset = Dataset.from_dict({"text": val_texts, "label": val_labels})
    
    train_dataset = train_dataset.map(tokenize_function, batched=True)
    val_dataset = val_dataset.map(tokenize_function, batched=True)
    
    # Load model
    model = AutoModelForSequenceClassification.from_pretrained(
        model_name, 
        num_labels=4,
        id2label={i: label for label, i in label_map.items()},
        label2id=label_map
    )
    
    # Training arguments
    training_args = TrainingArguments(
        output_dir="f:/Fullbright Scholarship/X-CloudSentinel/backend/models/checkpoints",
        num_train_epochs=3,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=8,
        warmup_steps=100,
        weight_decay=0.01,
        logging_dir="f:/Fullbright Scholarship/X-CloudSentinel/backend/models/logs",
        logging_steps=10,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
    )
    
    def compute_metrics(pred):
        labels = pred.label_ids
        preds = pred.predictions.argmax(-1)
        precision, recall, f1, _ = precision_recall_fscore_support(labels, preds, average='weighted')
        acc = accuracy_score(labels, preds)
        return {
            'accuracy': acc,
            'f1': f1,
            'precision': precision,
            'recall': recall
        }
    
    # Trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        compute_metrics=compute_metrics,
    )
    
    # Train
    print("Starting training...")
    trainer.train(resume_from_checkpoint=True)
    
    # Save model
    save_path = "f:/Fullbright Scholarship/X-CloudSentinel/backend/models/X-CloudSentinel-distilbert"
    print(f"Saving model to {save_path}...")
    model.save_pretrained(save_path)
    tokenizer.save_pretrained(save_path)
    print("Training complete!")

if __name__ == "__main__":
    train_model()

