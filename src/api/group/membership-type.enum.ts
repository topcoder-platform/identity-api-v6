export enum MembershipType {
  User = 1,
  Group = 2,
}

export class MembershipTypeHelper {
  static lowerName(type: MembershipType): string {
    return MembershipType[type].toLowerCase();
  }

  static getById(id: number): MembershipType | null {
    const values = Object.values(MembershipType).filter(
      (v) => typeof v === 'number',
    ) as number[];
    return values.includes(id) ? (id as MembershipType) : null;
  }

  static getByKey(key: string): MembershipType | null {
    if (!key || key.trim() === '') return null;
    const entry = Object.entries(MembershipType).find(
      ([enumKey]) => enumKey.toLowerCase() === key.toLowerCase(),
    );
    return entry
      ? MembershipType[entry[0] as keyof typeof MembershipType]
      : null;
  }
}
