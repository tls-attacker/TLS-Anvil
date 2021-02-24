export interface IItemProviderContext {
  currentPage: number;
  perPage: number;
  filter: any;
  sortBy: string;
  sortDesc: boolean;
  apiUrl: string;
}
