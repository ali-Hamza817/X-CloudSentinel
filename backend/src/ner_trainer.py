from transformers import AutoTokenizer, AutoModelForTokenClassification, TrainingArguments, Trainer
from transformers import DataCollatorForTokenClassification
import torch
import numpy as np
from datasets import Dataset, Features, Sequence, Value, ClassLabel
import os

class SentinelNER:
    """
    BERT-based Named Entity Recognition (NER) for Contextual Secret Detection.
    Identifies secret tokens within code based on programmatic context.
    """
    def __init__(self, model_name="distilbert-base-uncased"):
        self.label_list = ["O", "B-SECRET", "I-SECRET"]
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForTokenClassification.from_pretrained(
            model_name, num_labels=len(self.label_list)
        )

    def _generate_synthetic_ner_data(self, num_samples=500):
        print(f"Generating {num_samples} synthetic NER samples...")
        data = {"tokens": [], "ner_tags": []}
        
        # Templates for code snippets with secrets
        templates = [
            ("aws_access_key = \"{secret}\"", [0, 0, 0, 0, 0, 1]),
            ("password: {secret}", [0, 0, 1]),
            ("export GITHUB_TOKEN={secret}", [0, 0, 1]),
            ("db.connect(\"mysql://user:{secret}@localhost\")", [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]),
            ("print(\"hello world\")", [0, 0, 0, 0])
        ]

        for _ in range(num_samples):
            template_text, labels = templates[torch.randint(0, len(templates), (1,)).item()]
            secret = "AKIA" + "".join([str(torch.randint(0, 10, (1,)).item()) for _ in range(16)])
            
            # Simple whitespace tokenization for synthetic labels
            text = template_text.format(secret=secret)
            tokens = text.replace('"', ' " ').split()
            
            # Align labels (crude alignment for synthetic data)
            aligned_labels = [0] * len(tokens)
            for i, tok in enumerate(tokens):
                if secret in tok:
                    aligned_labels[i] = 1 # B-SECRET
            
            data["tokens"].append(tokens)
            data["ner_tags"].append(aligned_labels)

        return Dataset.from_dict(data)

    def train(self):
        dataset = self._generate_synthetic_ner_data()
        
        def tokenize_and_align_labels(examples):
            tokenized_inputs = self.tokenizer(examples["tokens"], truncation=True, is_split_into_words=True)
            labels = []
            for i, label in enumerate(examples["ner_tags"]):
                word_ids = tokenized_inputs.word_ids(batch_index=i)
                previous_word_idx = None
                label_ids = []
                for word_idx in word_ids:
                    if word_idx is None:
                        label_ids.append(-100)
                    elif word_idx != previous_word_idx:
                        label_ids.append(label[word_idx])
                    else:
                        label_ids.append(label[word_idx] if label[word_idx] == 0 else 2) # I-SECRET
                    previous_word_idx = word_idx
                labels.append(label_ids)
            tokenized_inputs["labels"] = labels
            return tokenized_inputs

        tokenized_dataset = dataset.map(tokenize_and_align_labels, batched=True)

        # Split dataset
        split_dataset = tokenized_dataset.train_test_split(test_size=0.1)
        train_dataset = split_dataset["train"]
        eval_dataset = split_dataset["test"]

        training_args = TrainingArguments(
            output_dir="f:/Fullbright Scholarship/X-CloudSentinel/backend/models/ner_checkpoints",
            eval_strategy="epoch",
            learning_rate=2e-5,
            per_device_train_batch_size=8,
            num_train_epochs=3,
            weight_decay=0.01,
            save_strategy="epoch"
        )

        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=eval_dataset,
            data_collator=DataCollatorForTokenClassification(self.tokenizer),
        )

        print("Starting NER Training...")
        trainer.train()
        
        save_path = "f:/Fullbright Scholarship/X-CloudSentinel/backend/models/X-CloudSentinel-ner"
        self.model.save_pretrained(save_path)
        self.tokenizer.save_pretrained(save_path)
        print(f"NER Model saved to {save_path}")

if __name__ == "__main__":
    ner = SentinelNER()
    ner.train()

