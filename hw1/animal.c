#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ANIMALS 32

// Animal structure 
typedef struct Animal {
    char type[10];             // Animal's type: dog, cat, cow 
    char name[20];             // Animal's name
    void (*sound)(char *name); // Function pointer for Animal's sound
} Animal;

void dog_sound(char *name) 
{
    printf("[DOG] %s says: Woof Woof!\n", name);
}

void cat_sound(char *name) 
{
    printf("[CAT] %s says: Meow!\n", name);
}

void cow_sound(char *name) 
{
    printf("[COW] %s says: Moo!\n", name);
}
 
void assign_sound_function(Animal *animal) 
{
    if (strcmp(animal->type, "dog") == 0) 
    {
        animal->sound = dog_sound;
    } 
    else if (strcmp(animal->type, "cat") == 0) 
    {
        animal->sound = cat_sound;
    } 
    else if (strcmp(animal->type, "cow") == 0) 
    {
        animal->sound = cow_sound;
    } 
    else 
    {
        fprintf(stderr, "Unknown animal type: %s\n", animal->type);
    }
}

int main(int argc, char *argv[]) 
{
    Animal *animals[MAX_ANIMALS];  
    int i;
    int animal_count = 0;          

    FILE* fp = fopen(argv[1], "r");
    if (fp == NULL) 
    {
        perror("Failed to open file");
        return 1;
    }

    while (animal_count < MAX_ANIMALS) 
    {
        Animal *animal = (Animal *) malloc(sizeof(Animal)); 
        if (animal == NULL) 
        {
            perror("Failed to allocate memory");
            return 1;
        }

        if (fscanf(fp, "%s %s", animal->type, animal->name) != 2) 
        {
            free(animal);  
            break;  
        }

        assign_sound_function(animal);

        animals[animal_count++] = animal;
        animal->sound(animal->name);
    }

    for (i = 0; i < animal_count; i++) 
    {
        free(animals[i]);
    }

    fclose(fp);

    return 0;
}
